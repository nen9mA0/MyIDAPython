import idautils
import idaapi
import idc

template = [ ["movsxd","imul","mov","add","movsx","imul","mov","add","movsx","movsx","movsx","movsx","mov"],
            ["movsxd","imul","mov","add","movsxd","imul","mov","add","movsxd","movsx","movsx","movsx","mov"],
            ["movsxd","imul","mov","add","movsxd","imul","mov","add","movsx","movsx","movsx","movsx","mov"],
            ["movsx","imul","mov","add","movsxd","imul","mov","add","movsxd","movsx","movsx","mov","mov"]  ]
template_op = [ [2,0,0,0,2,0,0,0,2,2,0,0,0],
                [2,0,0,0,2,0,0,0,2,2,0,0,0],
                [2,0,0,0,2,0,0,0,2,2,0,0,0],
                [2,0,0,0,2,0,0,0,2,2,0,0,0] ]
template_format = [ "%s = unk_689FA0[%s*0x7f + byte_686090[ %s*0x7f+%s[%s] ]]",
                    "%s = unk_689FA0[%s*0x7f + byte_686090[ %s*0x7f+%s[%s] ]]",
                    "%s = unk_689FA0[%s*0x7f + byte_686090[ %s*0x7f+%s[%s] ]]",
                    "%s = unk_689FA0[%s*0x7f + byte_686090[ %s*0x7f+%s[%s] ]]" ]

ea = ScreenEA()
result = []
for i in xrange(len(template)):
    result.append([])

begin = [0]*len(template)
template_index = [0]*len(template)
last_template_addr = ea

not_in_template = []


while True:
    if idaapi.isCode(idaapi.getFlags(ea)):
        flag = True
        cmd = idc.GetDisasm(ea)
        opcode = cmd.split(' ')[0]
        for i in xrange(len(template)):
            if opcode == template[i][ template_index[i] ]:
                flag = False
                if template_index[i] == 0:
                    begin[i] = ea
                if template_index[i] < len(template[i])-1:
                    template_index[i] += 1
                else:                               # if match a template
                    result[i].append( (begin[i],ea) )
                    tmp = idc.NextHead(last_template_addr)
                    if tmp >= begin[i]:
                        pass
                    else:
                        not_in_template.append( (tmp,begin[i]) )
                    last_template_addr = ea
                    for j in xrange(len(template)):
                        template_index[j] = 0
                    break                        # jump out
            else:
                template_index[i] = 0
        old_ea = ea
        ea = idc.NextHead(ea)
    else:
        break


'''
n = 0
print len(result)
for template_ret in result:
    fp.write("\ntemplate%d:\n" %n)
    n+=1

    #sub = template_ret[0][1] - template_ret[0][0]
    for ret in template_ret:
        fp.write( "%x:%x\n" %(ret[0],ret[1] ) )
        #if ret[1]-ret[0] != sub:
         #   print "%x:%x\n" %(ret[0],ret[1] )

fp.write("\n\nnot in template\n")
for m in not_in_template:
    fp.write("%x:%x\n" %(m[0],m[1]))
 '''
op = []
n = 0
for template_ret in result:
    op.append([])
    m = 0
    for ret in template_ret:
        ea = ret[0]
        op[n].append([])
        for i in template_op[n]:
            if i != 0:
                op[n][m].append( idc.get_operand_value(ea,i-1) )
            else:
                pass
            ea = idc.NextHead(ea)
        m += 1
    n += 1


fp = open("template1.txt","w+")

for op_m in op:
    for op_t in op_m:
        fp.write("%s = unk_689FA0[%s*0x7f + byte_686090[ %s*0x7f+%s[%s] ]]\n" % (hex(op_t[0]),hex(op_t[0]),hex(op_t[1]),hex(op_t[2]),hex(op_t[3])) )

print "done"
fp.close()