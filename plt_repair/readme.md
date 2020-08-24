这个脚本是做de1ctf 2020的re1时写的

因为plt表被动态加载，因此dump下gdb调试时的plt表来修复

使用方式：输入的filename为gdb中`x /na`的输出，其中n为dump的个数

示例：

```
0x800be80:      0x7fffff18f6e0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_>                                                               0x7fffff191420 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc>
0x800be90:      0x7fffff126050 <_ZSt17__throw_bad_allocv>                                                                                                    0x7fffff0fc6c0 <__cxa_begin_catch>
0x800bea0:      0x7fffff190be0 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv>                                                              0x7fffff1919b0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2ERKS4_>
0x800beb0:      0x7ffffebdaba0 <__memcmp_avx2_movbe>                                                                                                         0x7fffff126230 <_ZSt20__throw_length_errorPKc>
0x800bec0:      0x7fffff18f660 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2EOS4_>                                                                0x7fffff18f6c0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED2Ev>
0x800bed0:      0x7fffff18f7b0 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv>                                                               0x7ffffebdead0 <__memmove_avx_unaligned_erms>
0x800bee0:      0x7ffffea93430 <__GI___cxa_atexit> 0x7fffff0fbf10 <_ZdlPv>
0x800bef0:      0x7fffff17f210 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc>                                                                     0x7fffff0fde60 <_Znwm>
0x800bf00:      0x7ffffea804a0 <isalnum>        0x7fffff191ca0 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEmm>
0x800bf10:      0x7fffff17dd80 <_ZNSolsEPFRSoS_E>  0x7fffff18fce0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEmc>
0x800bf20:      0x7fffff1207e0 <_ZNSaIcED2Ev>   0x7ffffeb84c80 <__stack_chk_fail>
0x800bf30:      0x7fffff191bf0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2EPKcmRKS3_>                                                           0x7ffffeae7950 <__GI___libc_free>
0x800bf40:      0x7ffffea93120 <__GI_exit>      0x7fffff190bb0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEOS4_>
0x800bf50:      0x7fffff116460 <_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE>                          0x7fffff190870 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLERKS4_>
```

### repair_plt

脚本默认按照一行输出16字节的内容处理，因此若是64位程序，一行有2个plt表项，若是32位则一行有4个表项。脚本使用正则匹配每行表项个数，并根据该行的地址计算每个表项的地址（表项地址 = 本行地址 + 16/每行表项数 * 当前表项是本行的第几个）

脚本的修复方式是根据ScreenEA()获取当前指向的segment，计算当前segment的低16位（由addr_mask指定）是否与表项的低16位相同，若相同则计算表项的偏移（当前segment基地址+表项在内存中地址的低16位）。若该地址的名字是默认名字（sub_ off_ dword_等，在defalult_name中指定），则修改为plt的函数名

### restore_plt

用来还原repair_plt的修复结果的，流程跟repair_plt一样，只不过是最后判断名字的时候把非默认名字改为默认名字而已（默认名字格式由restore_name决定）