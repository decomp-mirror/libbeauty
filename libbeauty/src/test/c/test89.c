/* A very simple function to test external call() to putchar. */
#include <stdint.h>
#include <stdio.h>

int test89(void);

int test89(void) {
	puts("Hello1\n");
	puts("There2\n");
	return 0;
}

