#ifndef _DETOURHOOKING_UTILS_HPP
#define _DETOURHOOKING_UTILS_HPP

#include <cstdint>

namespace DetourHooking {
	constexpr std::size_t relJmpDistance = INT32_MAX;
	constexpr std::size_t relJmpLength = 5; // The length of an x86(-64) relative jmp
#ifdef __x86_64
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp
#endif

	std::size_t getPageSize();
	void* align(const void* addr, const std::size_t alignment);
	std::size_t pointerDistance(const void* a, const void* b);

	void writeRelJmp(void* location, const void* target);
#ifdef __x86_64
	void writeAbsJmp(void* location, const void* target);
#endif
	void forceMemCpy(void* dest, const void* src, std::size_t n);
	void forceMemSet(void* s, int c, std::size_t n);
}

#endif
