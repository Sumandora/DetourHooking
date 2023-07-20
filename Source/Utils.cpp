#include "Utils.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

std::size_t DetourHooking::GetPageSize()
{
	static const std::size_t pageSize = getpagesize();
	return pageSize;
}

void* DetourHooking::Align(const void* const addr, const std::size_t alignment)
{
	return (void*)(((std::size_t)addr) & ~(alignment - 1));
}

std::size_t DetourHooking::PointerDistance(const void* const a, const void* const b)
{
	return std::abs(reinterpret_cast<const char*>(b) - reinterpret_cast<const char*>(a));
}

void DetourHooking::Protect(const void* const addr, const std::size_t length, const int prot)
{
	const std::size_t pagesize = GetPageSize();
	void* aligned = Align(addr, pagesize);
	const std::int64_t alignDifference = PointerDistance(addr, aligned);
	mprotect(aligned, alignDifference + length, prot);
}

void DetourHooking::WriteRelJmp(void* const location, const void* const target)
{
	unsigned char jmpInstruction[] = {
		0xE9, 0x0, 0x0, 0x0, 0x0 // jmp goal
	};
	// Calculation for a relative jmp
	void* const jmpTarget = reinterpret_cast<void* const>(reinterpret_cast<const char* const>(target) - (reinterpret_cast<char* const>(location) + relJmpLength)); // Jumps always start at the ip, which has already increased
	std::memcpy(jmpInstruction + 1, &jmpTarget, sizeof(int32_t));
	std::memcpy(location, jmpInstruction, relJmpLength);
}

#ifdef __x86_64
void DetourHooking::WriteAbsJmp(void* const location, const void* const target)
{
	unsigned char absJumpInstructions[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, goal
		0xFF, 0xE0 // jmp rax
	};
	std::memcpy(absJumpInstructions + 2, &target, sizeof(void*));
	std::memcpy(location, absJumpInstructions, absJmpLength);
}
#endif
