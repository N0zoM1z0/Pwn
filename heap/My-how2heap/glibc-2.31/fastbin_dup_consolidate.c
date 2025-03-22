#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main() {
	void *ptr[7];
	// fill up tcache
	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

	
	void* p1 = calloc(1,0x40); // use calloc to prevent 'gain from tcache'

  	free(p1); // into fastbin

  	void* p3 = malloc(0x400); // largebin size to trigger fastbin consolidate

	assert(p1 == p3);

	free(p1); // double free p1

	void *p4 = malloc(0x400);

	assert(p4 == p3);
	// p3 && p4 all point to the same chunk

	return 0;
}
