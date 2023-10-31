#include <cassert>
#include <iostream>
#include <vector>

#include "DetourHooking.hpp"

#include "Common.hpp"

DetourHooking::Hook* factorialHook;
DetourHooking::Hook* sumHook;

long myFactorial(long a)
{
	return reinterpret_cast<FactorialFunc>(factorialHook->getTrampoline())(a) + 123;
}

long mySum(long a, long b)
{
	return reinterpret_cast<SumFunc>(sumHook->getTrampoline())(a, b) + 123;
}

int main()
{
	printf("------- Hooking Factorial -------\n");
	{
		printf("5! = %ld\n", factorial(5));
		assert(120 == factorial(5));

		factorialHook = new DetourHooking::Hook(factorial, myFactorial, INSTRUCTION_LENGTH);
		factorialHook->enable();
		assert(factorialHook->getError() == DetourHooking::Error::SUCCESS);
		printf("Hooked Factorial\n");

		printf("5! + 123 = %ld\n", factorial(5));
		assert(120 + 123 == factorial(5));
	}

	printf("------- Hooking Sum -------\n");
	{
		printf("2+5 = %ld\n", sum(2, 5));
		assert(7 == sum(2, 5));

		sumHook = new DetourHooking::Hook(reinterpret_cast<void*>(sum), reinterpret_cast<void*>(mySum), INSTRUCTION_LENGTH);
		sumHook->enable();
		assert(sumHook->getError() == DetourHooking::Error::SUCCESS);
		printf("Hooked Sum\n");

		printf("2+5 + 123 = %ld\n", sum(2, 5));
		assert(7 + 123 == sum(2, 5));
	}

	printf("------- Disabling Hooks -------\n");
	{
		factorialHook->disable();
		sumHook->disable();
		printf("Disabled both hooks\n");

		printf("5! = %ld\n", factorial(5));
		assert(120 == factorial(5));

		printf("2+5 = %ld\n", sum(2, 5));
		assert(7 == sum(2, 5));
	}

	printf("------- Finalizing Hooks -------\n");
	{
		printf("Deallocating memory by finalizing both hooks\n");
		delete factorialHook;
		delete sumHook;
	}

	return 0;
}