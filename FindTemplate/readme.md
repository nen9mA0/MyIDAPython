### 类型与方法

Template类可以接收list类型或文件名类型

* Find方法用于查找匹配的地址
* PrintResult方法用于打印地址查找的结果

### 模板格式

* 仅指定助记符

  ```
  mov
  add
  ```

* 指定助记符及一个寄存器操作数

  ```
  mov reg, void
  add void, reg
  ```

* 指定助记符及一个立即数

  ```
  add void, imm
  ```

* 指定助记符及一个指定的寄存器操作数

  ```
  mov reg(rax), void
  ```

* 指定助记符及一个指定的立即数操作数

  ```
  mov void, imm(0x10)
  ```


**注意**：由于IDA本身不区分rax eax 和 ax（使用get_operand_value获取的值是相同的），因此这里也只能将几个寄存器当成同样的来处理