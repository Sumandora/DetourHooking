#include "DetourHooking.hpp"

#include "MemoryPage.hpp"
#include "Utils.hpp"

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

	memoryPage = findMemory(original, instructionLength);
	if (!memoryPage) {
		error = Error::OUT_OF_MEMORY;
		return;
	}

	char* const location = reinterpret_cast<char*>(memoryPage->location);

	const std::size_t originalOffset = memoryPage->offset;
	std::size_t& offset = memoryPage->offset;

#ifdef __x86_64
	needsAbsoluteJmp = pointerDistance(hook, original) > relJmpDistance;

	if (needsAbsoluteJmp) { // Relative jumps can only cover +/- 2 GB, in case that isn't enough we write an absolute jump
		absJmp = location + offset;
		writeAbsJmp(absJmp, hook);
		offset += absJmpLength;
	} else {
		absJmp = nullptr;
	}
#endif

	forceMemCpy(location + offset, original, instructionLength); // Stolen bytes
	offset += instructionLength;

	writeRelJmp(location + offset, reinterpret_cast<char*>(original) + relJmpLength); // Back to the original
	offset += relJmpLength;

	trampoline = location + originalOffset
#ifdef __x86_64
		+ (needsAbsoluteJmp ? absJmpLength : 0)
#endif
		;

	error = Error::SUCCESS;
	enabled = false;
}

void Hook::enable()
{
	if (error != Error::SUCCESS || enabled)
		return;

#ifdef __x86_64
	if (needsAbsoluteJmp) {
		writeRelJmp(original, absJmp);
	} else {
		writeRelJmp(original, hook);
	}
#else
	writeRelJmp(original, hook);
#endif

	forceMemSet(reinterpret_cast<char*>(original) + relJmpLength, 0x90, instructionLength - relJmpLength);

	enabled = true;
}

void Hook::disable()
{
	if (error != Error::SUCCESS || !enabled)
		return;

	forceMemCpy(original, trampoline, instructionLength);

	enabled = false;
}

Hook::~Hook()
{
	if (enabled)
		disable();

	unmapMemoryPage(memoryPage);
}
