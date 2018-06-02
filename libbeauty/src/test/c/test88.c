/* A very simple function to test recursion. */

int test88(int value)
{
	if (1 >= value) return 1;
	return value + test88(value - 1);
}

