/* A very simple function to test one indirect call. */

int test87(int (*test) (int value))
{
	return test(10);
}

