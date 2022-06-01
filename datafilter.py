import idc
import ida_kernwin

# start = idc.AskAddr(ScreenEA(),"Start Address:")
# length = idc.AskLong(ItemSize(ScreenEA()),"Length:")
# datatype = idc.AskStr("b","Type:")

start = ida_kernwin.ask_addr(idc.get_screen_ea(),"Start Address:")
length = ida_kernwin.ask_long(idc.get_item_size(idc.get_screen_ea()),"Length:")
datatype = ida_kernwin.ask_str("b", 0, "Type:")

i = 1

if datatype == "B" or datatype == "b":
    # func = idc.Byte
    func = idc.get_wide_byte
elif datatype == "w" or datatype == "W":
    # func = idc.Word
    func = idc.get_wide_word
    i = 2
elif datatype == "d" or datatype == "D":
    # func = idc.Dword
    func = idc.get_wide_dword
    i = 4
elif datatype == "q" or datatype == "Q":
    # func = idc.Qword
    func = idc.get_qword
    i = 8
elif datatype == "f" or datatype == "F":
    func = idc.GetFloat
    i = 4
elif datatype == "lf" or datatype == "LF":
    func = idc.GetDouble
    i = 8
else:
    # func = idc.Byte
    func = idc.get_wide_byte

a = []
for n in range(0,length*i,i):
	a.append(func(start+n))
print("Totally Convert %d Bytes"%(len(a)))

print("[", end='')
if func != idc.GetFloat and func != idc.GetDouble:
    tmp = [hex(x) for x in a]
else:
    tmp = a
for i in range(len(tmp)-1):
    print("%s,"%tmp[i], end='')
print("%s"%tmp[len(tmp)-1], end='')
print("]")