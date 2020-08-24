import idc
import idautils
import idaapi
import os
import re

re_getitem = re.compile("0x[0-9a-f]+\s<\w*>")
re_getaddr = re.compile("0x[0-9a-f]+:")
addr_mask = 0xffff
default_name = ["sub_", "dword_", "qword_", "word_", "off_"]
restore_name = "off_%04X"

def in_default(name):
    res = False
    for defname in default_name:
        if name[:len(defname)] == defname:
            res = True
            break
    return res

filename = idc.AskStr("", "Input file name")
dirname = idautils.GetIdbDir()
if os.path.exists(filename):
    filepath = filename
elif os.path.exists(dirname+filename):
    filepath = dirname+filename
else:
    print("File Not Exist")
    exit()

items = []
with open(filename) as f:
    raw = f.read()
    lines = raw.split("\n")

    for i in lines:
        addr_raw = re_getaddr.search(i)
        if addr_raw != None:
            addr = int(addr_raw.group()[:-1], 16)
            funcs = re_getitem.findall(i)
            if funcs != []:
                func_num = len(funcs)
                addr_gap = 16 / func_num
                for j in range(len(funcs)):
                    item = []
                    item.append(addr+j*addr_gap)
                    func_addr, func_name = funcs[j].split()
                    item.append((int(func_addr,16), func_name.strip("<>")))
                    items.append(item)



if items != []:
    print("============Find PLT Table============")
    for i in items:
        print("%x: %x  %s" %(i[0], i[1][0], i[1][1]))
    print("======================================")
else:
    print("No PLT Table found")
    exit()

print("Use Lowest 16bits Matching")

currentEA = ScreenEA()

segstart = idc.SegStart(currentEA)
segend = idc.SegEnd(currentEA)

for i in items:
    item_addr = i[0]
    if (segstart&addr_mask) < (item_addr&addr_mask) and (segend&addr_mask) > (item_addr&addr_mask):
        patch_addr = (item_addr&addr_mask) + (segstart&(~addr_mask))
        prev_name = idc.get_name(patch_addr)
        if not in_default(prev_name):
            name = restore_name %(patch_addr&addr_mask)
            idc.MakeName(patch_addr, name)
            print("MakeName: %x  %s" %(patch_addr, name))