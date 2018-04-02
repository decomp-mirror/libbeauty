/* A very simple function to test movzbl 0x0,%eax. */
/* ZEXT */
#include <stdint.h>

static uint8_t mem1 = 0x12;

int test83() {
	return mem1;
}

