
kernel 从 v5.7.1开始就不再导出查询符号地址函数 kallsyms_lookup_name。 在一些情况下会造成问题，例如在符号上设置硬断点。

总结以下几种方法，得到kallsyms_lookup_name地址并调用。
1. 应用层查询/proc/kallsyms文件，取得kallsyms_lookup_name地址作为内核模块参数传递。
2. 利用KDB的函数kdbgetsymval
3. 利用kprobe
4. 利用livepatch

在特定场景下，可能有些方式失效，再选择其他方式。

已经包装成find_kallsyms_addr函数。
