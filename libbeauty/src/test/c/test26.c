/* A very simple function to test one call param that passes the value of a parameter. */

int test26b(int value2 );

int test26a(void)
{
	return test26b(15);
}

int test26b(int value2 )
{
	return value2 + 10;
}
