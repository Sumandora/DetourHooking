#include <cassert>
#include <iostream>

#include "DetourHooking.hpp"

long Factorial(long a)
{
	long b = a;
	for (long i = 2; i < a; i++)
		b *= i;
	return b;
}

typedef long (*FactorialFunc)(long);

Hook* factorialHook;

long MyFactorial(long a)
{
	return reinterpret_cast<FactorialFunc>(factorialHook->trampoline)(a) + 123;
}

long Sum(long a, long b)
{
	return a + b;
}

typedef long (*SumFunc)(long, long);

Hook* sumHook;

long MySum(long a, long b)
{
	return reinterpret_cast<SumFunc>(sumHook->trampoline)(a, b) + 123;
}

int main()
{
	{
		printf("5! = %ld\n", Factorial(5));
		assert(120 == Factorial(5));

		factorialHook = new Hook(reinterpret_cast<void*>(Factorial),
			reinterpret_cast<void*>(MyFactorial),
			8);
		factorialHook->Enable();
		assert(factorialHook->error == DETOURHOOKING_SUCCESS);
		printf("Hooked Factorial\n");

		printf("5! + 123 = %ld\n", Factorial(5));
		assert(120 + 123 == Factorial(5));
	}

	{
		printf("2+5 = %ld\n", Sum(2, 5));
		assert(7 == Sum(2, 5));

		sumHook = new Hook(reinterpret_cast<void*>(Sum),
			reinterpret_cast<void*>(MySum),
			8);
		sumHook->Enable();
		assert(sumHook->error == DETOURHOOKING_SUCCESS);
		printf("Hooked Sum\n");

		printf("2+5 + 123 = %ld\n", Sum(2, 5));
		assert(7 + 123 == Sum(2, 5));
	}

	{
		factorialHook->Disable();
		sumHook->Disable();
		printf("Disabled both hooks\n");

		printf("5! = %ld\n", Factorial(5));
		assert(120 == Factorial(5));

		printf("2+5 = %ld\n", Sum(2, 5));
		assert(7 == Sum(2, 5));
	}

	return 0;
}
