#include "DetourHooking.hpp"
#include <cstring>

#include "Utils.hpp"

using namespace DetourHooking;

Exception::Exception(Error error)
	: error(error)
{
}

Hook::Hook(
	ExecutableMalloc::MemoryManagerMemoryBlockAllocator& allocator,
	void* const original,
	const void* const hook,
	std::size_t instructionLength)
	: original(reinterpret_cast<std::uintptr_t>(original))
	, hook(reinterpret_cast<std::uintptr_t>(hook))
	, instructionLength(instructionLength)
	, memoryManager(allocator.getMemoryManager())
{
	if (instructionLength < minLength) {
		throw Exception(Error::INSUFFICIENT_LENGTH); // We won't be able to fit a near jmp
	}

#ifdef __x86_64
	needsTrampolineJump = pointerDistance(reinterpret_cast<std::uintptr_t>(hook), reinterpret_cast<std::uintptr_t>(original)) > relJmpDistance;
#endif

	unsigned char bytes[
#ifdef __x86_64
		(needsTrampolineJump ? absJmpLength : 0) +
#endif
		instructionLength + relJmpLength];
	std::size_t offset = 0;
	std::size_t bytesLength = sizeof(bytes) / sizeof(*bytes);

	memoryPage = allocator.getRegion(reinterpret_cast<std::uintptr_t>(original), bytesLength, memoryManager.requiresPermissionsForWriting());
#ifdef __x86_64
	if (needsTrampolineJump) { // Relative jumps can only cover +/- 2 GB, in case that isn't enough we write an absolute jump
		// Maybe the memory page is just close enough to the hook that we can save some space by making a relative jump
		bool needsAbsTrampolineJump = pointerDistance(this->hook, memoryPage->getFrom()) > relJmpDistance;
		if (needsAbsTrampolineJump) {
			writeAbsJmp(this->hook, bytes);
			offset += absJmpLength;
		} else {
			writeRelJmp(memoryPage->getFrom(), this->hook, bytes);
			offset += relJmpLength;
			memoryPage->resize(bytesLength - (absJmpLength - relJmpLength)); // We can now save some bytes because we can make a relative jump
		}
	}
#endif

	trampoline = memoryPage->getFrom() + offset;

	std::memcpy(bytes + offset, original, instructionLength); // Stolen bytes
	offset += instructionLength;

	writeRelJmp(memoryPage->getFrom() + offset, this->original + instructionLength, bytes + offset); // Back to the original

	memoryManager.write(memoryPage->getFrom(), bytes, bytesLength);

	if(memoryPage->isWritable())
		memoryPage->setWritable(false);
	enabled = false;
}

void Hook::enable() noexcept
{
	if (enabled)
		return;

	unsigned char bytes[relJmpLength];
#ifdef __x86_64
	if (needsTrampolineJump)
		writeRelJmp(original, memoryPage->getFrom(), bytes);
	else
#endif
		writeRelJmp(original, hook, bytes);

	if (memoryManager.requiresPermissionsForWriting()) {
		memoryManager.protect(align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, true, true });
		memoryManager.write(original, bytes, relJmpLength);
		memoryManager.protect(align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, false, true });
	} else
		memoryManager.write(original, bytes, relJmpLength);

	enabled = true;
}

void Hook::disable() noexcept
{
	if (!enabled)
		return;

	mprotect(reinterpret_cast<void*>(align(original, getpagesize())), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(reinterpret_cast<void*>(original), reinterpret_cast<const void*>(trampoline), instructionLength);

	enabled = false;
}

Hook::~Hook() noexcept
{
	if (enabled)
		disable();
}

bool Hook::writeRelJmp(std::uintptr_t location, std::uintptr_t target, unsigned char* bytes)
{
	// Jumps always start at the ip, which has already increased.
	// The theoretical overflow here is a non-issue as creating a hook at the end of the memory range is never going to happen.
	location += relJmpLength;
	// Calculation for a relative jmp
	std::size_t distance = pointerDistance(target, location);
	if (distance > relJmpDistance)
		return false;
	auto jmpTarget = static_cast<std::int32_t>(distance); // This cast is exactly why we need absolute jumps sometimes
	if (location > target) // Are we going backwards?
		jmpTarget *= -1;
	bytes[0] = '\xE9';
	std::memcpy(bytes + 1, &jmpTarget, sizeof(std::int32_t));
	return true;
}

#ifdef __x86_64
void Hook::writeAbsJmp(std::uintptr_t target, unsigned char* bytes)
{
	bytes[0] = '\x48';
	bytes[1] = '\xB8';
	std::memcpy(bytes + 2, &target, sizeof(void*));
	bytes[10] = '\xFF';
	bytes[11] = '\xE0';
}
#endif