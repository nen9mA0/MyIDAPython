import idautils
import idaapi
import idc

import pickle
import os

filepath = __file__
realpath = os.path.realpath(filepath)
current_dir = os.path.dirname(realpath)

reg_conf = os.path.join(current_dir, "intel_reg.conf")
with open(reg_conf, "rb") as f:
    reg_dict = pickle.load(f)

# In Instruction, oprand (0, -1) means nothing
class Instruction(object):
    operand_type = {"void":0, "reg":1, "mem":2, "phrase":3, "displ":4, "imm":5, "far":6, "near":7, "idpspec0":8, "idpspec1":9, "idpspec2":10, "idpspec3":11, "idpspec4":12, "idpspec5":13}
    opcode = ""
    def __init__(self, opcode, oprand1, oprand2):           # tuple (oprand_type, oprand_number)
        self.opcode = opcode
        self.oprand1 = oprand1
        self.oprand2 = oprand2

    def __eq__(self, rhs):
        ret = False
        if self.opcode == rhs.opcode:
            if self.CmpOprand(self.oprand1, rhs.oprand1) and self.CmpOprand(self.oprand2, rhs.oprand2):
                ret = True
        return ret

    def __str__(self):
        ret = self.opcode
        if self.oprand1 == None or self.oprand1[0] == 0:
            ret += " None"
        else:
            ret += " %d:%s" %(self.oprand1[0], self.oprand1[1])
        if self.oprand2 == None or self.oprand2[0] == 0:
            ret += " None"
        else:
            ret += " %d:%s" %(self.oprand2[0], self.oprand2[1])
        return ret

    def CmpOprand(self, op1, op2):
        ret = False
        try:
            if op1[0] != 0:             # if we have specify the template's oprand
                if op1[0] == op2[0]:    # type compare
                    if op1[1] != -1:  # if we have specify the op value
                        if op1[1] == op2[1]:
                            ret = True
                    else:
                        ret = True
            else:                           # if we don't specify the template's oprand
                ret = True
        except Exception as e:
            print(e)
        return ret

class InstructionParser(Instruction):
    def __init__(self, ins):
        tmp = ins.split()
        if len(tmp) == 1:
            opcode = tmp[0]
            oprand1 = (0, -1)
            oprand2 = (0, -1)
        elif len(tmp) == 2:
            opcode = tmp[0]
            oprand1 = self.GetOprand(tmp[1].rstrip(','))
            oprand2 = (0, -1)
        elif len(tmp) == 3:
            opcode = tmp[0]
            oprand1 = self.GetOprand(tmp[1].rstrip(','))
            oprand2 = self.GetOprand(tmp[2])
        super(InstructionParser, self).__init__(opcode, oprand1, oprand2)

    def GetBeforeDelim(self, mystr, delim):
        index = mystr.find(delim)
        if index != -1:
            return mystr[:index]
        else:
            return mystr

    def GetDelim(self, mystr, ldelim, rdelim):
        lindex = mystr.find(ldelim)
        rindex = mystr.find(rdelim)
        if lindex == -1:
            llim = 0
        else:
            llim = lindex+1
        if rindex == -1:
            rlim = len(mystr)
        else:
            rlim = rindex
        return mystr[llim:rlim]

    def ProcessOprandStr(self, oprand_type, oprand_str):
        num = -1
        if oprand_type == 1:     # reg
            if reg_dict.has_key(oprand_str):
                return reg_dict[oprand_str]
            elif reg_dict.has_key(oprand_str[1:]):
                return reg_dict[oprand_str[1:]]
            else:
                raise ValueError("No Register Named %s" %oprand_str)
        else:                    # other cases return number
            if oprand_str[:2] == "0x":
                try:
                    num = int(oprand_str, 16)
                except Exception as e:
                    print("Cannot Convert %s To Hex" %oprand_str)
            else:
                try:
                    num = int(oprand_str, 10)
                except Exception as e:
                    print("Cannot Convert %s To Decimal" %oprand_str)
        return num

    def GetOprand(self, raw_oprand):
        oprand = raw_oprand.strip()
        oprand_type_str = self.GetBeforeDelim(oprand, '(')
        if self.operand_type.has_key(oprand_type_str):
            oprand_type = self.operand_type[oprand_type_str]
        else:
            raise ValueError("Wrong Oprand Type")
        oprand_str = self.GetDelim(oprand, '(', ')')
        
        op_num = -1
        if oprand_str != "":
            op_num = self.ProcessOprandStr(oprand_type, oprand_str)
        return (oprand_type, op_num)

class Template:
    ins = []
    result = []             # Used to save found result
    def __init__(self, obj):
        if isinstance(obj, str):
            self.lst = []
            with open(obj) as f:
                tmp = f.read()
                self.lst = tmp.splitlines()
        elif isinstance(obj, list):
            self.lst = obj
        self.Parse()

    def __str__(self):
        ret = ""
        for i in self.ins:
            ret += str(i) + "\n"
        return ret

    def ParseLine(self, mystr):
        return InstructionParser(mystr)

    def Parse(self):
        for i in self.lst:
            self.ins.append(self.ParseLine(i))

    def GetCurrentIns(self, mnem, ea):
        oprand1 = (idc.get_operand_type(ea, 0), idc.get_operand_value(ea, 0))
        oprand2 = (idc.get_operand_type(ea, 1), idc.get_operand_value(ea, 1))
        return Instruction(mnem, oprand1, oprand2)

    def Find(self, start_addr, end_addr):
        ea = start_addr
        old_ea = start_addr

        match_index = 0                         # current matching index
        matching_ins = self.ins[match_index]    # current matching instruction
        match_begin = start_addr                # start address of first matched instruction
        match_ea = []                           # list of all instruction's ea

        max_index = len(self.ins)

        while True:
            if idaapi.isCode(idaapi.getFlags(ea)):
                mnem = idc.GetMnem(ea)                  # for quick compare, do not create Instruction every ins
                if mnem == matching_ins.opcode:
                    current_ins = self.GetCurrentIns(mnem, ea)
                    if matching_ins == current_ins:
                        if match_index == 0:
                            match_begin = ea
                        match_index += 1
                        match_ea.append(ea)             # push current ea into match_ea
                        if match_index >= max_index:    # if template matched
                            self.result.append(match_ea)
                            match_ea = []               # new ea list
                            match_index = 0
                            ea = match_begin            # reset ea to match_begin, so that we won't omission any matched instructions
                        else:
                            pass    # if not all matched yet
                    else:
                        if not match_ea == []:
                            match_ea = []                   # reset match_ea
                            match_index = 0
                else:
                    if not match_ea == []:
                        match_ea = []                   # reset match_ea
                        match_index = 0
            else:
                if not match_ea == []:
                    match_ea = []                   # reset match_ea
                    match_index = 0

            matching_ins = self.ins[match_index]
            old_ea = ea
            ea = idc.NextHead(ea)
            if ea > end_addr:
                break
        return self.result

    def PrintResult(self):
        print("=========Result=========")
        n = 1
        for ea_lst in self.result:
            print("==== %d ====" %n)
            for ea in ea_lst:
                print("%x" %ea)
            n += 1


if __name__ == "__main__":          # example
    tp = Template(["mov","add","mov","add void, reg(r12)","mov","and","add","mov","and","and","cmp","jz","pop","pop","add","jmp"])
    print tp
    print("===========")
    segment_addr_start = 0x400770
    segment_addr_end = 0x40A462
    result = tp.Find(segment_addr_start, segment_addr_end)
    tp.PrintResult()

    n = 0
    for ins in tp.result:
        n += 1
        print("==== %d ====" %n)
        for ea in ins:
            mnem = idc.GetMnem(ea)
            current_ins = tp.GetCurrentIns(mnem, ea)
            print(current_ins)