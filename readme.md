该项目是本人平时不写一到打比赛的时候就疯狂造轮子的一些程序

* datafilter   用于提取某个程序地址的n个数据并转换为python的列表格式，数据类型可以指定为Byte Word Dword Qword Float Double
* float2num   是某次比赛造的从二进制到float/double以及其反向转换的轮子（但其实并没有必要，当时不知道IDAPython直接有这个接口）
* plt_repair   是用于逆向编译选项为PIC的文件时修复导入表的程序，但其实可以通过加载程序时勾选加载选项，取消第二个选项的勾来正常解析plt表。
* get_template   是用于匹配一个指令模板的程序
* instruction_data   不知道什么时候写的，就是拿来获取mov操作数的，没什么卵用
* FindTemplate   目前最大的一个轮子，用来查找一个指令序列，可以只进行助记符匹配，也可以指定参数的类型（寄存器、立即数等）进行匹配，具体的可以看Template.py的main，给了个sample

