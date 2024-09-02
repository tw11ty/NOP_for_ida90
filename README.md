# NOP_for_ida90

对https://github.com/RussianPanda95/NOP_Plugin/tree/main 项目的二次开发。能够在ida9.0对mips/x86架构进行nop操作。

ida9.0 python ida_idaapi删除了get_inf_structure，于是使用idc.get_inf_attr()来获取处理器类型以及位数。

对于大小端没有直接的返回值来获取，后面会继续完善。

