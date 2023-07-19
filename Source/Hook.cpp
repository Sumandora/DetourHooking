#include "DetourHooking.hpp"

#include "MemoryPage.hpp"
#include "Utils.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <vector>

#include <sys/mman.h>

using namespace DetourHooking;

Hook::Hook(void* const original, const void* const hook, std::size_t instructionLength)
{
	this->original = original;
	this->hook = hook;
	this->instructionLength = instructionLength;

	if (instructionLength < minLength) {
		error = Error::INSUFFICIENT_LENGTH; // We won't be able to fit a near jmp
		return;
	}

	memoryPage = FindMemory(original, instructionLength);
	if (!memoryPage) {
		error = Error::OUT_OF_MEMORY;
		return;
	}
	memoryPage->hooks++;

	char* const location = reinterpret_cast<char*>(memoryPage->location);

	const std::size_t originalOffset = memoryPage->offset;
	std::size_t& offset = memoryPage->offset;

#ifdef __x86_64
	needsAbsoluteJmp = PointerDistance(hook, original) > relJmpDistance;

	if (needsAbsoluteJmp) { // Relative jumps can only cover +/- 2 GB, in case that isn't enough we write an absolute jump
		absJmp = location + offset;
		WriteAbsJmp(absJmp, hook);
		offset += absJmpLength;
	} else {
		absJmp = nullptr;
	}
#endif

	memcpy(location + offset, original, instructionLength); // Stolen bytes
	offset += instructionLength;

	WriteRelJmp(location + offset, reinterpret_cast<char*>(original) + relJmpLength); // Back to the original
	offset += relJmpLength;

	trampoline = location + originalOffset
#ifdef __x86_64
		+ (needsAbsoluteJmp ? absJmpLength : 0)
#endif
		;

	// We are done here, make it read-only
	Protect(memoryPage->location, GetPageSize(), PROT_READ | PROT_EXEC);

	error = Error::SUCCESS;
	enabled = false;
}

void Hook::Enable()
{
	if (error != Error::SUCCESS || enabled)
		return;

	Protect(original, instructionLength, PROT_READ | PROT_WRITE | PROT_EXEC);

#ifdef __x86_64
	if (needsAbsoluteJmp) {
		WriteRelJmp(original, absJmp);
	} else {
		WriteRelJmp(original, hook);
	}
#else
	WriteRelJmp(original, hook);
#endif

	memset(reinterpret_cast<char*>(original) + relJmpLength, 0x90, instructionLength - relJmpLength);

	Protect(original, instructionLength, PROT_READ | PROT_EXEC);
	enabled = true;
}

void Hook::Disable()
{
	if (error != Error::SUCCESS || !enabled)
		return;

	Protect(original, instructionLength, PROT_READ | PROT_WRITE | PROT_EXEC);

	memcpy(original, trampoline, instructionLength);

	Protect(original, instructionLength, PROT_READ | PROT_EXEC);
	enabled = false;
}

Hook::~Hook()
{
	if (enabled)
		Disable();

	memoryPage->hooks--;

	if (memoryPage->hooks <= 0) {
		UnmapMemoryPage(memoryPage);
	}
}
