#include "Utils.hpp"

#include <cmath>
#include <cstddef>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

std::size_t DetourHooking::GetPageSize()
{
	static const std::size_t pageSize = getpagesize();
	return pageSize;
}

void* DetourHooking::Align(const void* addr, const std::size_t alignment)
{
	return (void*)(((std::size_t)addr) & ~(alignment - 1));
}

std::ptrdiff_t DetourHooking::PointerDistance(const void* a, const void* b)
{
	return std::abs(reinterpret_cast<const char*>(b) - reinterpret_cast<const char*>(a));
}

void DetourHooking::Protect(const void* addr, const std::size_t length, const int prot)
{
	const std::size_t pagesize = GetPageSize();
	void* aligned = Align(addr, pagesize);
	const std::ptrdiff_t alignDifference = PointerDistance(addr, aligned);
	mprotect(aligned, alignDifference + length, prot);
}

void DetourHooking::WriteRelJmp(void* location, const void* target)
{
	unsigned char jmpInstruction[] = {
		0xE9, 0x0, 0x0, 0x0, 0x0 // jmp goal
	};
	// Calculation for a relative jmp
	void* jmpTarget = reinterpret_cast<void*>(PointerDistance(target, reinterpret_cast<char*>(location) + relJmpLength)); // Jumps always start at the rip, which has already increased
	std::memcpy(jmpInstruction + 1, &jmpTarget, sizeof(int32_t));
	std::memcpy(location, jmpInstruction, relJmpLength);
}

void DetourHooking::WriteAbsJmp(void* location, const void* target)
{
	unsigned char absJumpInstructions[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, goal
		0xFF, 0xE0 // jmp rax
	};
	std::memcpy(absJumpInstructions + 2, &target, sizeof(void*));
	std::memcpy(location, absJumpInstructions, absJmpLength);
}