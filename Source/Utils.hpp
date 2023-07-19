#ifndef DETOURHOOKING_UTILS_HPP
#define DETOURHOOKING_UTILS_HPP

#include <cstdint>

namespace DetourHooking {
	constexpr std::size_t relJmpDistance = INT32_MAX;
	constexpr std::size_t relJmpLength = 5; // The length of an x86(-64) relative jmp
#ifdef __x86_64
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp
#endif

	std::size_t GetPageSize();
	void* Align(const void* addr, const std::size_t alignment);
	std::size_t PointerDistance(const void* a, const void* b);
	void Protect(const void* addr, const std::size_t length, const int prot);

	void WriteRelJmp(void* location, const void* target);
#ifdef __x86_64
	void WriteAbsJmp(void* location, const void* target);
#endif
}

#endif
