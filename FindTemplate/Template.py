import idautils
import idaapi
import idc


template = [ 
    ["mov", "add", "mov", "add", "mov", "and", "add", "mov", "and", "and", "cmp", "jz"],
    ["mov", "add", "mov", "add", "mov", "and", "add", "mov", "and", "and", "cmp", "jz", "pop", "pop", "add", "jmp"]
    ]

class Template:
    operand_type = {0:"void", 1:"reg", 2:"mem", 3:"phrase", 4:"displ", 5:"imm", 6:"far", 7:"near", 8:"idpspec0", 9:"idpspec1", 10:"idpspec2", 11:"idpspec3", 12:"idpspec4", 13:"idpspec5"}

    def __init__(self, template):
        self.template = template

        self.result = []
        for i in xrange(len(template)):
            self.result.append([])

        self.begin = [0]*len(template)
        self.template_index = [0]*len(template)
        self.last_template_addr = 0
        self.not_in_template = []

    def ParseTemplate(self, s):
        token = s.split()
        

    def Find(self, start_addr, end_addr):
        ea = start_addr
        self.last_template_addr = ea
        while True:
            if idaapi.isCode(idaapi.getFlags(ea)):
                old_ea = ea
                opcode = idc.print_insn_mnem(ea)
                for i in xrange(len(self.template_index)):
                    self.template_index[i] = 0
                for i in xrange(len(self.template)):
                    if opcode == self.template[i][ self.template_index[i] ]:
                        if self.template_index[i] == 0:
                            self.begin[i] = ea
                        if self.template_index[i] < len(self.template[i])-1:
                            self.template_index[i] += 1
                        else:                               # if match a template
                            self.result[i].append( (self.begin[i],ea) )
                            tmp = idc.NextHead(self.last_template_addr)
                            if tmp >= self.begin[i]:
                                pass
                            else:
                                self.not_in_template.append( (tmp, self.begin[i]) )
                            self.last_template_addr = ea
                            self.template_index[i] = 0
                            break                        # jump out
                    else:
                        self.template_index[i] = 0
                old_ea = ea
                ea = idc.NextHead(ea)
                if ea > end_addr:
                    break
            else:
                ea = idc.NextHead(ea)
                if ea > end_addr:
                    break

    def __str__(self):
        ret = ""
        for i in xrange(len(self.template)):
            ret += "==== template%d ====\n" %(i+1)
            for j in self.result[i]:
                ret += "%x, %x\n" %(j[0], j[1])
        return ret

def PatchJz(jz_addr):
    binary = idc.GetManyBytes(jz_addr, idc.get_item_size(jz_addr))
    if binary[0] == chr(0x74):
        idc.PatchByte(jz_addr, 0xeb)
        print "%x: patch success" %jz_addr
    else:
        print "%x: patch failed" %jz_addr

segment_addr_start = 0x400770
segment_addr_end = 0x40A462
tmp = Template(template)
tmp.Find(segment_addr_start, segment_addr_end)
print tmp
# for result in tmp.result:
#     for i in result[0]:
#         jz_addr = i[1]
#         PatchJz(jz_addr)

# ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
# cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# for i in tmp.result[0]:
#     jz_addr = i[1]
#     binary = idc.GetManyBytes(jz_addr, idc.get_item_size(jz_addr))
#     print cs.disasm(binary, 0)