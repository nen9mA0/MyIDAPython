import idc

ea = ScreenEA()

jmp_ins = ["endbr64", "jmp"]

for funcea in Functions(SegStart(ea), SegEnd(ea)):
    function_name = GetFunctionName(funcea)
    for (startea, endea) in Chunks(funcea):
        if 
            opcodelst.append( idc.print_insn_mnem(head) )

    if flag:
        