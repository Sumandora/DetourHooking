#include "DetourHooking.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

constexpr size_t relJmpDistance = INT32_MAX;
constexpr size_t relJmpLength = 5; // The length of an x86-64 relative jmp
constexpr size_t absJmpLength = 12; // The length of an x86-64 absolute jmp

size_t GetPageSize()
{
	static const size_t pageSize = getpagesize();
	return pageSize;
}

void* Align(const void* addr, const size_t alignment)
{
	return (void*)(((size_t)addr) & ~(alignment - 1));
}

void Protect(const void* addr, const size_t length, const int prot)
{
	const size_t pagesize = GetPageSize();
	void* aligned = Align(addr, pagesize);
	const size_t alignDifference = (char*)addr - (char*)aligned;
	mprotect(aligned, alignDifference + length, prot);
}

uint64_t PointerDistance(const void* a, const void* b)
{
	return std::abs(reinterpret_cast<const char*>(b) - reinterpret_cast<const char*>(a));
}

struct MemoryPage {
	void* location;
	size_t offset; // How much has been written there?
};

void* FindUnusedMemory(const void* preferredLocation)
{
	for (size_t offset = 0; offset <= relJmpDistance; offset += GetPageSize())
		for (int sign = -1; sign <= 2; sign += 2) {
			void* pointer = mmap(
				reinterpret_cast<char*>(Align(preferredLocation, GetPageSize())) + offset * sign,
				GetPageSize(),
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
				-1,
				0);
			if (pointer != MAP_FAILED)
				return pointer;
		}
	return nullptr;
}

MemoryPage* FindMemory(const void* preferredLocation, const size_t instructionLength)
{
	static std::vector<MemoryPage> pages;

	for (MemoryPage& memoryPage : pages) {
		const uint64_t distance = PointerDistance(memoryPage.location, preferredLocation);
		if (GetPageSize() - memoryPage.offset >= instructionLength + relJmpLength + (distance > relJmpDistance ? absJmpLength : 0))
			if (distance <= relJmpDistance) {
				// We used this one before, it should be read-only
				Protect(memoryPage.location, GetPageSize(), PROT_READ | PROT_WRITE | PROT_EXEC);
				return &memoryPage;
			}
	}

	void* newLocation = FindUnusedMemory(preferredLocation);

	if (!newLocation)
		return nullptr;

	if (PointerDistance(newLocation, preferredLocation) > relJmpDistance) {
		munmap(newLocation, GetPageSize());
		return nullptr;
	}

	return &pages.emplace_back(MemoryPage { newLocation, 0 });
}

void WriteRelJmp(void* location, const void* target)
{
	unsigned char jmpInstruction[] = {
		0xE9, 0x0, 0x0, 0x0, 0x0 // jmp goal
	};
	// Calculation for a relative jmp
	void* jmpTarget = reinterpret_cast<void*>(reinterpret_cast<const char*>(target) - (reinterpret_cast<char*>(location) + relJmpLength)); // Jumps always start at the rip, which has already increased
	memcpy(jmpInstruction + 1, &jmpTarget, relJmpLength - 1 /* E9 */);
	memcpy(location, jmpInstruction, relJmpLength);
}

void WriteAbsJmp(void* location, const void* target)
{
	unsigned char absJumpInstructions[] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, goal
		0xFF, 0xE0 // jmp rax
	};
	memcpy(absJumpInstructions + 2, &target, sizeof(void*));
	memcpy(location, absJumpInstructions, absJmpLength);
}

Hook::Hook(void* original, void* hook, size_t instructionLength)
{
	this->original = original;
	this->hook = hook;
	this->instructionLength = instructionLength;

	if (instructionLength < DETOURHOOKING_MIN_LENGTH)
		error = DETOURHOOKING_INSUFFICIENT_LENGTH; // We won't be able to fit a near jmp

	MemoryPage* memoryPage = FindMemory(original, instructionLength);
	if (!memoryPage)
		error = DETOURHOOKING_OUT_OF_MEMORY;

	const size_t originalOffset = memoryPage->offset;
	size_t& offset = memoryPage->offset;

	needsAbsoluteJmp = PointerDistance(hook, original) > relJmpDistance;

	if (needsAbsoluteJmp) { // Relative jumps can only cover +/- 2 GB, in case that isn't enough we write an absolute jump
		absJmp = reinterpret_cast<char*>(memoryPage->location) + offset;
		WriteAbsJmp(absJmp, hook);
		offset += absJmpLength;
	}

	memcpy(reinterpret_cast<char*>(memoryPage->location) + offset, original, instructionLength); // Stolen bytes
	offset += instructionLength;

	WriteRelJmp(reinterpret_cast<char*>(memoryPage->location) + offset,
		reinterpret_cast<char*>(original) + relJmpLength); // Back to the original
	offset += relJmpLength;

	trampoline = reinterpret_cast<char*>(memoryPage->location) + originalOffset + (needsAbsoluteJmp ? absJmpLength : 0);

	// We are done here, make it read-only
	Protect(memoryPage->location, GetPageSize(), PROT_READ | PROT_EXEC);

	error = DETOURHOOKING_SUCCESS;
}

void Hook::Enable()
{
	if (error)
		return;

	Protect(original, instructionLength, PROT_READ | PROT_WRITE | PROT_EXEC);

	if (needsAbsoluteJmp) {
		WriteRelJmp(original, absJmp);
	} else {
		WriteRelJmp(original, hook);
	}

	memset(reinterpret_cast<char*>(original) + relJmpLength, 0x90, instructionLength - relJmpLength);

	Protect(original, instructionLength, PROT_READ | PROT_EXEC);
}

void Hook::Disable()
{
	if (error)
		return;

	Protect(original, instructionLength, PROT_READ | PROT_WRITE | PROT_EXEC);

	memcpy(original, trampoline, instructionLength);

	Protect(original, instructionLength, PROT_READ | PROT_EXEC);
}
