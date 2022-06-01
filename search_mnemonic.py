import idautils
import idaapi
import idc
import ida_kernwin
import ida_bytes

ea = idc.get_screen_ea()
mnemonic = ida_kernwin.ask_str("", 0, "mnemonic:")

while True:
    if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        flag = True
        cmd = idc.generate_disasm_line(ea, 0)
        opcode = cmd.split(' ')[0]
        if mnemonic == opcode:
            print("%x: %s" %(ea, cmd))
            ida_kernwin.jumpto(ea)
            break
    old_ea = ea
    ea = idc.next_head(ea)