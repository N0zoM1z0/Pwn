off-by-one / off-by-null

参考:
[ctfwiki](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/off-by-one/)
[ZIKH26](https://www.cnblogs.com/ZIKH26/articles/16422131.html)

# 介绍
off-by-one是一种特殊的堆溢出漏洞 即只能溢出一个字节的情况

# off-by-one 漏洞原理
off-by-one 是指单字节缓冲区溢出，这种漏洞的产生往往与边界验证不严和字符串操作有关，当然也不排除写入的 size 正好就只多了一个字节的情况。
其中边界验证不严通常包括
- 使用循环语句向堆块中写入数据时，循环的次数设置错误 导致多写入了一个字节。
- **字符串操作**不合适 (例如前面read后面strcpy则会多cpy一个\x00)

一般来讲 单字节溢出较难利用 但由于linux堆的ptmalloc的一些特性 使得off-by-one成为堆漏洞的一个trick

# off-by-one 利用思路
1. 溢出字节可以控制为任意字节: 通过修改大小造成chunk之间出现重叠 从而泄露/覆盖其他块数据 也可以使用NULL字节溢出的方法
2. 溢出字节为NULL字节: 通常溢出NULL字节可以使`prev_in_use`位被清 让前块被认为是free块
 (1)可以选择`unlink`攻击
 (2)由于这时`prev_size`会被启用 所以可以伪造`prev_size` 造成chunk之间的重叠
 此方法的关键在于: unlink的时候没有检查以`prev_size`找到的chunk的大小与`prev_size`是否一致

libc-2.29之后 代码加入了检测
```c
/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      /* 后两行代码在最新版本中加入，则 2 的第二种方法无法使用，但是 2.28 及之前都没有问题 */
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```




---
---

后面找题来跟着做一做
这种很考验堆的综合能力... 怎么布局...