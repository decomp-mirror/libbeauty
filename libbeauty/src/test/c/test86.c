/* A very simple function to test relocation records that refer to readonly data sections. */
#include <stdint.h>
#include <stdio.h>

int test86(void);

int test86(void) {
	const char *hello = "Hello World\n";
	return 0;
}

