/* A very simple function to test structure accesses. */
#include <stdint.h>
#include <stdio.h>

int value1 = 1;
int value2 = 2;

int test91(void);

int test91(void) {
	int a;
	int b;
	a = value1;
	b = value2;
	return a + b;
}

