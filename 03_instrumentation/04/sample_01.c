/*
 * Initial demonstration program.
 * This program just loops forever incrementing by one each time.
 * The purpose of this code is teaching the basics of Frida
 */

#include <stdio.h>
#include <unistd.h>

// function that prints an integer
void
myfunc(int n)
{
  printf("Number: %d\n", n);
}

int main()
{
  int i = 0;

  printf("myfunc is at %p\n", myfunc); // get function pointer

  while(1)
  {
    // myfunc(i++);
    sleep(1);
  }
}

