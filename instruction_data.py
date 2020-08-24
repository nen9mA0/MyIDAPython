import idautils
import idaapi
import idc

ea = ScreenEA()
if idaapi.isCode(idaapi.getFlags(ea)):
    cmd = idc.GetDisasm(ea)
    prt_str = "Current cmd: %s" %cmd
    select = idc.ask_yn(ASKBTN_YES,prt_str)
    if select == ASKBTN_YES:
        length = idc.AskLong(1,"Instruction Number:")
        if length > 0:
            n = 0
            print ""
            oplist = []
            for i in xrange(length):
                if idaapi.isCode(idaapi.getFlags(ea)):
                    n += 1
                    cmd = idc.GetDisasm(ea)
                    print cmd
                    if cmd[:3] == "mov":
                        op1 = idc.get_operand_value(ea,0)
                        op2 = idc.get_operand_value(ea,1)
                        oplist.append((op1,op2))
                        #print hex(op1),hex(op2)
                else:
                    break
                ea = idc.NextHead(ea)
            print "Process %d Instructions"%n
            oplist.sort()
        for (i,j) in oplist:
            print hex(i)+"\t",
        print ""
        for (i,j) in oplist:
            print hex(j)+"\t",
        print "\n[",
        for (i,j) in oplist:
            print "0x%x,"%j,
        print "]"
else:
    msg("Please Select An Instruction")