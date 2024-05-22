#ifndef DETOURHOOKING_UTILS_HPP
#define DETOURHOOKING_UTILS_HPP

#include <cstdint>
#include <limits>

namespace DetourHooking {
	constexpr std::size_t relJmpDistance = std::numeric_limits<std::int32_t>::max();
	constexpr std::size_t relJmpLength = 5; // The length of an x86(-64) relative jmp
#ifdef __x86_64
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp
#endif

	[[nodiscard]] std::uintptr_t align(std::uintptr_t addr, std::size_t alignment);
	[[nodiscard]] std::size_t pointerDistance(std::uintptr_t a, std::uintptr_t b);

}

#endif
