/*
 * Demonstration program.
 * This program loops forever increasing a counter. It calls a function
 * that just returns a number based on the counter and prints it.
 * This code is only for demonstration of basic usage of the FRIDA framework.
 */

#include <stdio.h>
#include <unistd.h>

int myfunc(int number)
{
	return number;
}

void
lazy(int seconds)
{
	sleep(seconds);
}


int main()
{
	int i = 0;

	printf("Myfunc is at %p\n", myfunc);
	printf("lazy is at %p\n", lazy);
	while(1)
	{
		printf("Number: %d\n", myfunc(i++));
		lazy(1);
	}
}
