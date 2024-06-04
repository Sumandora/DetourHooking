#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include "ExecutableMalloc/MemoryManagerAllocator.hpp"

#include <cstdint>
#include <cstring>
#include <memory>
#include <sys/mman.h>

namespace DetourHooking {
	constexpr std::size_t minLength = 5; // The length of an x86-64 near jmp
	constexpr std::size_t relJmpDistance = std::numeric_limits<std::int32_t>::max();
	constexpr std::size_t relJmpLength = 5; // The length of an x86(-64) relative jmp
#ifdef __x86_64
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp
#endif

	namespace detail {
		constexpr std::uintptr_t align(std::uintptr_t addr, const std::size_t alignment)
		{
			return addr - addr % alignment;
		}

		constexpr std::size_t pointerDistance(std::uintptr_t a, std::uintptr_t b)
		{
			return std::max(a, b) - std::min(a, b);
		}
	}

	enum class Error {
		INSUFFICIENT_LENGTH = 0, // The `instructionLength` was too small
	};

	class Exception : std::exception {
		Error error;

	public:
		explicit Exception(Error error)
			: error(error)
		{
		}
		[[nodiscard]] Error getError() const noexcept { return error; }
	};

	class Hook {
	private:
		std::uintptr_t original;
		std::uintptr_t hook;
		std::size_t instructionLength;

#ifdef __x86_64
		bool needsTrampolineJump;
#endif
		std::unique_ptr<ExecutableMalloc::MemoryRegion> memoryPage;
		const MemoryManager::MemoryManager& memoryManager;

		bool enabled;

		std::uintptr_t trampoline;

	protected:
		static bool writeRelJmp(std::uintptr_t location, std::uintptr_t target, unsigned char* bytes)
		{
			// Jumps always start at the ip, which has already increased.
			// The theoretical overflow here is a non-issue as creating a hook at the end of the memory range is never going to happen.
			location += relJmpLength;
			// Calculation for a relative jmp
			std::size_t distance = detail::pointerDistance(target, location);
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
		static void writeAbsJmp(std::uintptr_t target, unsigned char* bytes)
		{
			bytes[0] = '\x48';
			bytes[1] = '\xB8';
			std::memcpy(bytes + 2, &target, sizeof(void*));
			bytes[10] = '\xFF';
			bytes[11] = '\xE0';
		}
#endif
	public:
		// May throw exceptions
		Hook(
			ExecutableMalloc::MemoryManagerMemoryBlockAllocator& allocator,
			void* original,
			const void* hook,
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
			needsTrampolineJump = detail::pointerDistance(reinterpret_cast<std::uintptr_t>(hook), reinterpret_cast<std::uintptr_t>(original)) > relJmpDistance;
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
				bool needsAbsTrampolineJump = detail::pointerDistance(this->hook, memoryPage->getFrom()) > relJmpDistance;
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

			if (memoryPage->isWritable())
				memoryPage->setWritable(false);
			enabled = false;
		}

		void enable() noexcept
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
				memoryManager.protect(detail::align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, true, true });
				memoryManager.write(original, bytes, relJmpLength);
				memoryManager.protect(detail::align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, false, true });
			} else
				memoryManager.write(original, bytes, relJmpLength);

			enabled = true;
		}
		void disable() noexcept
		{
			if (!enabled)
				return;

			mprotect(reinterpret_cast<void*>(detail::align(original, getpagesize())), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
			memcpy(reinterpret_cast<void*>(original), reinterpret_cast<const void*>(trampoline), instructionLength);

			enabled = false;
		}
		~Hook() noexcept
		{
			if (enabled)
				disable();
		}

		[[nodiscard]] constexpr bool isEnabled() const noexcept { return enabled; }
		[[nodiscard]] constexpr std::uintptr_t getTrampoline() const noexcept { return trampoline; }
	};
}

#endif
