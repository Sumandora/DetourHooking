#include "Utils.hpp"

#include <cmath>
#include <cstring>


std::uintptr_t DetourHooking::align(std::uintptr_t addr, const std::size_t alignment)
{
	return addr - addr % alignment;
}

std::size_t DetourHooking::pointerDistance(std::uintptr_t a, std::uintptr_t b)
{
	return std::max(a, b) - std::min(a, b);
}
