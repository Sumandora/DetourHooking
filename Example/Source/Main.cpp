#include <cassert>
#include <cstdint>
#include <print>

#include "DetourHooking.hpp"
#include "ExecutableMalloc/MemoryManagerAllocator.hpp"
#include "MemoryManager/LinuxMemoryManager.hpp"

using FactorialFunc = int64_t (*)(int64_t);
using SumFunc = int64_t (*)(int64_t, int64_t);

// NOLINTNEXTLINE(cert-err58-cpp)
static MemoryManager::LinuxMemoryManager<false, true, true> memory_manager;

// NOLINTNEXTLINE(cert-err58-cpp)
static ExecutableMalloc::MemoryManagerAllocator allocator{ memory_manager };

template <bool NeedsTrampoline>
using HookT = DetourHooking::Hook<NeedsTrampoline, decltype(memory_manager)>;

static HookT<true>* factorial_hook;
static HookT<false>* sum_hook;

static int64_t factorial(int64_t a)
{
	int64_t b = a;
	for (int64_t i = 2; i < a; i++)
		b *= i;
	return b;
}

static int64_t sum(int64_t a, int64_t b)
{
	return a + b;
}

static int64_t my_factorial(int64_t a)
{
	return reinterpret_cast<FactorialFunc>(factorial_hook->get_trampoline())(a) + 123;
}

static int64_t my_sum(int64_t /*a*/, int64_t /*b*/)
{
	return 1337;
}

static void hook_factorial()
{
	std::println("5! = {}", factorial(5));
	assert(120 == factorial(5));

	factorial_hook = new HookT<true>(allocator, reinterpret_cast<void*>(factorial), reinterpret_cast<void*>(my_factorial),
#ifdef __x86_64
		8
#else
		6
#endif
	);
	factorial_hook->enable();
	std::println("Hooked Factorial");

	std::println("5! + 123 = {}", factorial(5));
	assert(120 + 123 == factorial(5));
}

static void hook_sum()
{
	std::println("2+5 = {}", sum(2, 5));
	assert(7 == sum(2, 5));

	sum_hook = new HookT<false>(allocator, reinterpret_cast<void*>(sum), reinterpret_cast<void*>(my_sum),
#ifdef __x86_64
		8
#else
		6
#endif
	);
	sum_hook->enable();
	std::println("Hooked Sum");

	std::println("1337 = {}", sum(2, 5));
	assert(1337 == sum(2, 5));
}

static void disable_hooks()
{
	factorial_hook->disable();
	sum_hook->disable();
	std::println("Disabled both hooks");

	std::println("5! = {}", factorial(5));
	assert(120 == factorial(5));

	std::println("2+5 = {}", sum(2, 5));
	assert(7 == sum(2, 5));
}

static void finalize_hooks()
{
	std::println("Deallocating memory by finalizing both hooks");
	delete factorial_hook;
	delete sum_hook;
}

int main()
{
	std::println("------- Hooking Factorial -------");
	hook_factorial();

	std::println("------- Hooking Sum -------");
	hook_sum();

	std::println("------- Disabling Hooks -------");
	disable_hooks();

	std::println("------- Finalizing Hooks -------");
	finalize_hooks();

	return 0;
}
