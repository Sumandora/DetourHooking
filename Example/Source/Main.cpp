#include <cassert>
#include <cstdint>
#include <print>

#include "DetourHooking.hpp"
#include "ExecutableMalloc/MemoryManagerAllocator.hpp"
#include "MemoryManager/LinuxMemoryManager.hpp"

using FactorialFunc = int64_t (*)(int64_t);
using SumFunc = int64_t (*)(int64_t, int64_t);

// NOLINTNEXTLINE(cert-err58-cpp)
static MemoryManager::LinuxMemoryManager<false, true, true> memoryManager;

// NOLINTNEXTLINE(cert-err58-cpp)
static ExecutableMalloc::MemoryManagerAllocator allocator{ memoryManager };

template <bool NeedsTrampoline>
using HookT = DetourHooking::Hook<NeedsTrampoline, decltype(memoryManager)>;

static HookT<true>* factorialHook;
static HookT<false>* sumHook;

static int64_t Factorial(int64_t a)
{
	int64_t b = a;
	for (int64_t i = 2; i < a; i++)
		b *= i;
	return b;
}

static int64_t Sum(int64_t a, int64_t b)
{
	return a + b;
}

static int64_t MyFactorial(int64_t a)
{
	return reinterpret_cast<FactorialFunc>(factorialHook->getTrampoline())(a) + 123;
}

static int64_t MySum(int64_t /*a*/, int64_t /*b*/)
{
	return 1337;
}

static void hookFactorial()
{
	std::println("5! = {}", Factorial(5));
	assert(120 == Factorial(5));

	factorialHook = new HookT<true>(allocator, reinterpret_cast<void*>(Factorial), reinterpret_cast<void*>(MyFactorial),
#ifdef __x86_64
		8
#else
		6
#endif
	);
	factorialHook->enable();
	std::println("Hooked Factorial");

	std::println("5! + 123 = {}", Factorial(5));
	assert(120 + 123 == Factorial(5));
}

static void hookSum()
{
	std::println("2+5 = {}", Sum(2, 5));
	assert(7 == Sum(2, 5));

	sumHook = new HookT<false>(allocator, reinterpret_cast<void*>(Sum), reinterpret_cast<void*>(MySum),
#ifdef __x86_64
		8
#else
		6
#endif
	);
	sumHook->enable();
	std::println("Hooked Sum");

	std::println("1337 = {}", Sum(2, 5));
	assert(1337 == Sum(2, 5));
}

static void disableHooks()
{
	factorialHook->disable();
	sumHook->disable();
	std::println("Disabled both hooks");

	std::println("5! = {}", Factorial(5));
	assert(120 == Factorial(5));

	std::println("2+5 = {}", Sum(2, 5));
	assert(7 == Sum(2, 5));
}

static void finalizeHooks()
{
	std::println("Deallocating memory by finalizing both hooks");
	delete factorialHook;
	delete sumHook;
}

int main()
{
	std::println("------- Hooking Factorial -------");
	hookFactorial();

	std::println("------- Hooking Sum -------");
	hookSum();

	std::println("------- Disabling Hooks -------");
	disableHooks();

	std::println("------- Finalizing Hooks -------");
	finalizeHooks();

	return 0;
}
