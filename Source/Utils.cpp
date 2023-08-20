#include "Utils.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#include "ForceWrite.hpp"

std::size_t DetourHooking::getPageSize()
{
	static const std::size_t pageSize = getpagesize();
	return pageSize;
}

void* DetourHooking::align(const void* const addr, const std::size_t alignment)
{
	return (void*)(((std::size_t)addr) & ~(alignment - 1));
}

std::size_t DetourHooking::pointerDistance(const void* const a, const void* const b)
{
	return std::abs(reinterpret_cast<const char*>(b) - reinterpret_cast<const char*>(a));
}

void DetourHooking::writeRelJmp(void* const location, const void* const target)
{
	unsigned char jmpInstruction[] = {
		0xE9, 0x0, 0x0, 0x0, 0x0 // jmp goal
	};
	// Calculation for a relative jmp
	void* const jmpTarget = reinterpret_cast<void* const>(reinterpret_cast<const char* const>(target) - (reinterpret_cast<char* const>(location) + relJmpLength)); // Jumps always start at the ip, which has already increased
	std::memcpy(jmpInstruction + 1, &jmpTarget, sizeof(int32_t));
	forceMemCpy(location, jmpInstruction, relJmpLength);
}

#ifdef __x86_64
void DetourHooking::writeAbsJmp(void* const location, const void* const target)
{
	unsigned char absJumpInstructions[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, goal
		0xFF, 0xE0 // jmp rax
	};
	std::memcpy(absJumpInstructions + 2, &target, sizeof(void*));
	forceMemCpy(location, absJumpInstructions, absJmpLength);
}
#endif

void DetourHooking::forceMemCpy(void* dest, const void* src, std::size_t n)
{
	for (std::size_t i = 0; i < n; i++) {
		ForceWrite::write<char>(reinterpret_cast<char*>(dest) + i, *(reinterpret_cast<const char*>(src) + i));
	}
}

void DetourHooking::forceMemSet(void* s, int c, std::size_t n)
{
	for (std::size_t i = 0; i < n; i++) {
		ForceWrite::write<char>(reinterpret_cast<char*>(s) + i, c);
	}
}