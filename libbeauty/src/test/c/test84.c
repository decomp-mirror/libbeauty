/* A very simple function to test external call() to putchar. */
#include <stdint.h>
#include <stdio.h>

int test84(void);

int test84(void) {
	putchar(0x64);
	return 0;
}

