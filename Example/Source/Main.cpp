#include <cassert>
#include <iostream>
#include <vector>

#include "DetourHooking.hpp"
#include "ExecutableMalloc/MemoryManagerAllocator.hpp"
#include "MemoryManager/LinuxMemoryManager.hpp"

typedef long (*FactorialFunc)(long);
typedef long (*SumFunc)(long, long);

MemoryManager::LinuxMemoryManager<false, true, true> memoryManager;
ExecutableMalloc::MemoryManagerAllocator allocator{ memoryManager };

template<bool NeedsTrampoline>
using HookT = DetourHooking::Hook<NeedsTrampoline, decltype(memoryManager)>;

HookT<true>* factorialHook;
HookT<false>* sumHook;

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
	return reinterpret_cast<FactorialFunc>(factorialHook->getTrampoline())(a) + 123;
}

long MySum(long a, long b)
{
	return 1337;
}

int main()
{
	printf("------- Hooking Factorial -------\n");
	{
		printf("5! = %ld\n", Factorial(5));
		assert(120 == Factorial(5));

		factorialHook = new HookT<true>(allocator, reinterpret_cast<void*>(Factorial), reinterpret_cast<void*>(MyFactorial),
#ifdef __x86_64
			8
#else
			6
#endif
		);
		factorialHook->enable();
		printf("Hooked Factorial\n");

		printf("5! + 123 = %ld\n", Factorial(5));
		assert(120 + 123 == Factorial(5));
	}

	printf("------- Hooking Sum -------\n");
	{
		printf("2+5 = %ld\n", Sum(2, 5));
		assert(7 == Sum(2, 5));

		sumHook = new HookT<false>(allocator, reinterpret_cast<void*>(Sum), reinterpret_cast<void*>(MySum),
#ifdef __x86_64
			8
#else
			6
#endif
		);
		sumHook->enable();
		printf("Hooked Sum\n");

		printf("1337 = %ld\n", Sum(2, 5));
		assert(1337 == Sum(2, 5));
	}

	printf("------- Disabling Hooks -------\n");
	{
		factorialHook->disable();
		sumHook->disable();
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