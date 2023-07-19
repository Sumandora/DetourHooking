#include <cassert>
#include <iostream>

#include "DetourHooking.hpp"

typedef long (*FactorialFunc)(long);
typedef long (*SumFunc)(long, long);

DetourHooking::Hook* factorialHook;
DetourHooking::Hook* sumHook;

long Factorial(long a)
{
	long b = a;
	for (long i = 2; i < a; i++)
		b *= i;
	return b;
}

long Sum(long a, long b)
{
	return a + b;
}

long MyFactorial(long a)
{
	return reinterpret_cast<FactorialFunc>(factorialHook->trampoline)(a) + 123;
}

long MySum(long a, long b)
{
	return reinterpret_cast<SumFunc>(sumHook->trampoline)(a, b) + 123;
}

int main()
{
	printf("------- Hooking Factorial -------\n");
	{
		printf("5! = %ld\n", Factorial(5));
		assert(120 == Factorial(5));

		factorialHook = new DetourHooking::Hook(reinterpret_cast<void*>(Factorial), reinterpret_cast<void*>(MyFactorial),
#ifdef __x86_64
			8
#else
			6
#endif
		);
		factorialHook->Enable();
		assert(factorialHook->error == DetourHooking::Error::SUCCESS);
		printf("Hooked Factorial\n");

		printf("5! + 123 = %ld\n", Factorial(5));
		assert(120 + 123 == Factorial(5));
	}

	printf("------- Hooking Sum -------\n");
	{
		printf("2+5 = %ld\n", Sum(2, 5));
		assert(7 == Sum(2, 5));

		sumHook = new DetourHooking::Hook(reinterpret_cast<void*>(Sum), reinterpret_cast<void*>(MySum),
#ifdef __x86_64
			8
#else
			6
#endif
		);
		sumHook->Enable();
		assert(sumHook->error == DetourHooking::Error::SUCCESS);
		printf("Hooked Sum\n");

		printf("2+5 + 123 = %ld\n", Sum(2, 5));
		assert(7 + 123 == Sum(2, 5));
	}

	printf("------- Disabling Hooks -------\n");
	{
		factorialHook->Disable();
		sumHook->Disable();
		printf("Disabled both hooks\n");

		printf("5! = %ld\n", Factorial(5));
		assert(120 == Factorial(5));

		printf("2+5 = %ld\n", Sum(2, 5));
		assert(7 == Sum(2, 5));
	}

	printf("------- Finalizing Hooks -------\n");
	{
		printf("Deallocating memory by finalizing both hooks\n");
		delete factorialHook;
		delete sumHook;
	}

	return 0;
}
