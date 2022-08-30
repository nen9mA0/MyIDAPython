import ida_kernwin
import idc
import idautils
import ida_bytes
import idaapi
import json
import os
import copy

class HexPattern(object):
    def __init__(self, byte_seq):
        self.byte_seq = byte_seq
        # get length
        new_byte_seq = []
        for byte in byte_seq:
            if not byte.isspace():
                new_byte_seq.append(byte)
        self.hex_len = len(new_byte_seq) // 2

        mask = []
        # mask
        i = 0
        byte_mask = 0
        for j in range(len(new_byte_seq)):
            byte = new_byte_seq[j]
            if byte == '?':
                byte_mask = byte_mask << 4
                new_byte_seq[j] = "0"
            else:
                byte_mask = byte_mask << 4
                byte_mask |= 0xf
            i += 1
            if i == 2:
                mask.append(byte_mask & 0xff)
                byte_mask = 0
                i = 0

        new_byte_seq = "".join(new_byte_seq)
        self.mask = bytes(mask)
        self.hex = bytes.fromhex(new_byte_seq)
        self.find_lst = []
        self.do_find = False

    def Find(self, start, end):
        self.do_find = True
        tmp_start = start
        while True:
            ea = idaapi.bin_search(tmp_start, end, self.hex, self.mask, idaapi.BIN_SEARCH_FORWARD,idaapi.BIN_SEARCH_NOCASE)
            if ea == 0xffffffffffffffff:
                break
            else:
                self.find_lst.append(ea)
                tmp_start = ea+1
        return self.find_lst

    def __str__(self):
        mystr = ""
        mystr += "pattern: "
        mystr += self.byte_seq + "\n"
        mystr += "hex    : "
        mystr += str(self.hex) + "\n"
        mystr += "mask   : "
        tmp = ""
        for i in range(self.hex_len):
            tmp += "%02X " %self.mask[i]
        mystr += tmp + "\n"
        return mystr

    def __repr__(self):
        return str(self)


class PatternPair(object):
    def __init__(self, original, changed, iscode):
        if original.hex_len != changed.hex_len:
            raise ValueError("Original Length Not Equal To Changed Length")
        self.original = original
        self.changed = changed
        self.iscode = iscode
        self.changelog = []
        self.hex_len = original.hex_len

    def Replace(self, start, end):
        self.find(start, end)
        for addr in self.original.find_lst:
            if self.iscode:
                if not ida_bytes.is_code(addr):
                    continue
            ida_bytes.patch_bytes(addr, self.changed.hex)
            change = {}
            change["original"] = self.original.byte_seq
            change["changed"] = self.changed.byte_seq
            change["addr"] = addr
            self.changelog.append(change)
            print("Addr: %x" %addr)
            print("%s change to %s" %(self.original.hex, self.changed.hex))

    def Find(self, start, end):
        if not self.original.do_find:
            self.original.Find(start, end)
        return self.original.find_lst

    def Revert(self, addr):
        mybytes = ida_bytes.get_bytes(addr, self.hex_len)
        if mybytes == self.changed.hex:
            ida_bytes.patch_bytes(addr, self.original.hex)
            print("Addr: %x" %addr)
            print("%s revert to %s" %(self.changed.hex, self.original.hex))

    def __str__(self):
        mystr = ""
        mystr += "original:\n"
        mystr += str(self.original)
        mystr += "changed: \n"
        mystr += str(self.changed)
        return mystr

    def __repr__(self):
        return str(self)


class Finder(object):
    def __init__(self, dct):
        segment_dct = {}
        if "segments" in dct:
            segments = dct["segments"]
            for name in segments:
                start = idc.get_segm_by_sel(idc.selector_by_name(name))
                end = idc.get_segm_end(start)
                segment_dct[name] = (start, end)
        else:
            for ea in idautils.Segments():
                start = idc.get_segm_start(ea)
                end = idc.get_segm_end(ea)
                name = idc.get_segm_name(start)
                segment_dct[name] = (start, end)
        self.segment_dct = segment_dct

        pattern_lst = []
        patterns = dct["pattern"]
        for pattern in patterns:
            if pattern["type"] == "hex" and pattern["enable"]:
                original_hex = HexPattern(pattern["original"])
                changed_hex = HexPattern(pattern["changed"])
                if "iscode" in pattern:
                    iscode = pattern["iscode"]
                else:
                    iscode = False
                pattern_lst.append(PatternPair(original_hex, changed_hex, iscode))
        self.pattern_lst = pattern_lst

    def FindAll(self):
        find_dct = {}
        for name in self.segment_dct:
            start, end = self.segment_dct[name]
            tmp_dct = self.Find(start, end)
            for pattern_pair in tmp_dct:
                if pattern_pair in find_dct:
                    find_dct[pattern_pair].extend(tmp_dct[pattern_pair])
                else:
                    find_dct[pattern_pair] = tmp_dct[pattern_pair]
        return find_dct
            

    def Find(self, start, end):
        tmp_dct = {}
        for pattern_pair in self.pattern_lst:
            find_lst = pattern_pair.Find(start, end)
            if pattern_pair in tmp_dct:
                raise ValueError("")
            tmp_dct[pattern_pair] = find_lst
        return tmp_dct

    def ReplaceAll(self):
        changelog = []
        for name in self.segment_dct:
            start, end = self.segment_dct[name]
            for pattern_pair in self.pattern_lst:
                pattern_pair.Replace(start, end)
                changelog.extend(pattern_pair.changelog)
        return changelog

    def PrintAll(self):
        find_dct = self.FindAll()
        for pattern_pair in find_dct:
            print("===== Pattern =====")
            print("%s" %(pattern_pair.original))
            find_lst = find_dct[pattern_pair]
            for addr in find_lst:
                print("%x" %addr)


    def __str__(self):
        mystr = ""
        for pattern in self.pattern_lst:
            mystr += "===========\n"
            mystr += str(pattern)
        return mystr

    def __repr__(self):
        return str(self)


if __name__ == "__main__":
    filename = ida_kernwin.ask_file(False, "", "Choose Json File")

    with open(filename) as f:
        dct = json.load(f)

    if dct["type"] == "pattern":
        finder = Finder(dct)

        act = dct["action"]
        if act == "find":
            finder.PrintAll()
        elif act == "replace":
            changelog = finder.ReplaceAll()

            dir_name = os.path.dirname(filename)
            json_filename = os.path.basename(filename)
            index = json_filename.rfind(".")
            backup_filename = json_filename[:index] + "_patch_backup.json"
            backup_file = os.path.join(dir_name, backup_filename)

            flag = True
            if os.path.exists(backup_file):
                try:
                    with open(backup_file, "r") as f:
                        content = json.load(f)
                    content["changelog"].extend(changelog)
                    flag = False
                except:
                    pass
            if flag:
                content = {}
                content["type"] = "backup"
                content["changelog"] = changelog
            with open(backup_file, "w") as f:
                json.dump(content, f)
        elif dct["type"] == "backup":
            for change in dct["changelog"]:
                changed_hex = HexPattern(change["changed"])
                original_hex = HexPattern(change["original"])
                pattern_pair = PatternPair(original_hex, changed_hex)
                pattern_pair.Revert(change["addr"])

            backup_file = filename
            dct["changelog"].clear()
            with open(backup_file, "w") as f:
                json.dump(dct, f)
