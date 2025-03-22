#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	
	char* a = malloc(0x512);
	printf("chunk A @ %p\n",a);
	char* b = malloc(0x256);
	char *c;
	free(a);
	c = malloc(0x500);
	printf("chunk C @ %p\n",c);
	return 0;
}
/*
➜  My-how2heap gcc -g first_fit.c -o first_fit   
➜  My-how2heap ./first_fit 
chunk A @ 0x55a4eac4e2a0
chunk C @ 0x55a4eac4e2a0
*/
