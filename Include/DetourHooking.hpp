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
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp

	namespace detail {
#ifdef __x86_64
		constexpr bool Is64Bit = true;
#else
		constexpr bool Is64Bit = false;
#endif

		constexpr std::uintptr_t align(std::uintptr_t addr, std::size_t alignment)
		{
			return addr - addr % alignment;
		}

		constexpr std::size_t pointerDistance(std::uintptr_t a, std::uintptr_t b)
		{
			return std::max(a, b) - std::min(a, b);
		}

		static std::int32_t calculateJumpOffset(std::uintptr_t location, std::size_t instructionLength, std::uintptr_t target)
		{
			// Jumps always start at the ip, which has already increased.
			// The theoretical overflow here is a non-issue as creating a hook at the end of the memory range is never going to happen.
			location += instructionLength;

			// Calculation for a relative jmp:
			std::size_t distance = detail::pointerDistance(target, location);
			if (distance > relJmpDistance)
				throw std::bad_cast{}; // Missing distance check?????

			auto jmpTarget = static_cast<std::int32_t>(distance); // This cast is exactly why we need absolute jumps sometimes
			if(jmpTarget != distance)
				throw std::bad_cast{}; // Missing distance check?????

			if (location > target) // Are we going backwards?
				jmpTarget *= -1;
			return jmpTarget;
		}

		static bool writeRelJmp(std::uintptr_t location, std::uintptr_t target, unsigned char* bytes)
		{
			std::int32_t jmpTarget = calculateJumpOffset(location, relJmpLength, target);
			bytes[0] = '\xE9';
			std::memcpy(bytes + 1, &jmpTarget, sizeof(std::int32_t));
			return true;
		}

		static void writeAbsJmp(std::uintptr_t target, unsigned char* bytes)
		{
			bytes[0] = '\x48';
			bytes[1] = '\xB8';
			std::memcpy(bytes + 2, &target, sizeof(void*));
			bytes[10] = '\xFF';
			bytes[11] = '\xE0';
		}
	}

	template <bool NeedsTrampoline, typename MemMgr>
		requires MemoryManager::Reader<MemMgr> && MemoryManager::Writer<MemMgr> && (!MemMgr::RequiresPermissionsForWriting || MemoryManager::Protector<MemMgr>)
	class Hook {
	private:
		std::uintptr_t original;
		std::uintptr_t hook;

		std::unique_ptr<ExecutableMalloc::MemoryRegion> memoryRegion;
		const MemMgr& memoryManager;

		bool enabled;

		std::size_t instructionLength;
		[[no_unique_address]] std::conditional_t<NeedsTrampoline, std::uintptr_t, std::unique_ptr<std::byte[]>> trampoline;

		void writeJmp(std::uintptr_t location, std::uintptr_t target, std::size_t& offset, unsigned char* bytes) {
			if constexpr(detail::Is64Bit) {
				// If the target is too far away then we need an absolute jump
				bool needsAbsJmp = detail::pointerDistance(location + relJmpLength, target) > relJmpDistance;
				if (needsAbsJmp) {
					detail::writeAbsJmp(target, bytes);
					offset += absJmpLength;
					return;
				}
			}

			detail::writeRelJmp(location, target, bytes);
			offset += relJmpLength;
			if constexpr(detail::Is64Bit) {
				memoryRegion->resize(memoryRegion->getTo() - memoryRegion->getFrom() - (absJmpLength - relJmpLength)); // We can now save some bytes because we made a relative jump
			}

		}

	public:
		// May throw exceptions
		template<typename = int>
		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			void* original,
			const void* hook,
			std::size_t instructionLength)
			: original(reinterpret_cast<std::uintptr_t>(original))
			, hook(reinterpret_cast<std::uintptr_t>(hook))
			, instructionLength(instructionLength)
			, memoryManager(allocator.getMemoryManager())
		{
			if (instructionLength < minLength) {
				throw std::exception{}; // We won't be able to fit a near jmp
			}

			// Relative jumps can only cover +/- 2 GB, if the target is too far away, we need a memory page
			std::size_t regionSize = 0;

			if constexpr (detail::Is64Bit) {
				bool needsJmpIndirection = detail::pointerDistance(reinterpret_cast<std::uintptr_t>(hook), reinterpret_cast<std::uintptr_t>(original)) > relJmpDistance;

				if (needsJmpIndirection)
					regionSize += detail::Is64Bit ? absJmpLength : relJmpLength; // For 64-bit, this could be an absolute jmp. We may later decrease the size for the region, when this turns out to be achievable with a relative jmp
			}

			if constexpr (NeedsTrampoline) {
				regionSize += instructionLength; // The stolen bytes
				regionSize += detail::Is64Bit ? absJmpLength : relJmpLength; // It is unlikely, but in theory the top of our block is reachable with a x64 relative jmp but the bottom isn't, we later shrink the region
			}

			if(regionSize > 0) {
				unsigned char bytes[regionSize];
				std::size_t offset = 0;

				memoryRegion = allocator.getRegion(reinterpret_cast<std::uintptr_t>(original), regionSize, MemMgr::RequiresPermissionsForWriting);

				if constexpr (detail::Is64Bit) {
					writeJmp(memoryRegion->getFrom(), this->hook, offset, bytes);
				}

				if constexpr (NeedsTrampoline) {
					trampoline = memoryRegion->getFrom() + offset;

					memoryManager.read(this->original, bytes + offset, instructionLength); // Stolen bytes
					offset += instructionLength;

					writeJmp(memoryRegion->getFrom() + offset, this->original + instructionLength, offset, bytes + offset);
				}

				memoryManager.write(memoryRegion->getFrom(), bytes, offset);

				if (memoryRegion->isWritable())
					memoryRegion->setWritable(false);
			}

			if constexpr(!NeedsTrampoline) {
				trampoline = std::unique_ptr<std::byte[]>(new std::byte[instructionLength]);

				memoryManager.read(this->original, trampoline.get(), instructionLength); // Stolen bytes
			}

			enabled = false;
		}

		void enable() noexcept
		{
			if (enabled)
				return;

			unsigned char bytes[relJmpLength];
			if constexpr(detail::Is64Bit) {
				if(memoryRegion) {
					bool needsJmpIndirection = detail::pointerDistance(reinterpret_cast<std::uintptr_t>(hook), reinterpret_cast<std::uintptr_t>(original)) > relJmpDistance;

					if (needsJmpIndirection) {
						detail::writeRelJmp(original, memoryRegion->getFrom(), bytes);
						goto write;
					}
				}
			}

			detail::writeRelJmp(original, hook, bytes);

			write:
			if constexpr (MemMgr::RequiresPermissionsForWriting) {
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
			std::byte bytes[instructionLength];

			if constexpr (NeedsTrampoline) {
				memoryManager.read(trampoline, bytes, instructionLength);
			} else {
				memcpy(bytes, trampoline.get(), instructionLength);
			}

			if constexpr (MemMgr::RequiresPermissionsForWriting) {
				memoryManager.protect(detail::align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, true, true });
				memoryManager.write(original, bytes, instructionLength);
				memoryManager.protect(detail::align(original, memoryManager.getPageGranularity()), memoryManager.getPageGranularity(), { true, false, true });
			} else
				memoryManager.write(original, bytes, instructionLength);

			enabled = false;
		}
		~Hook() noexcept
		{
			if (enabled)
				disable();
		}

		[[nodiscard]] constexpr bool isEnabled() const noexcept { return enabled; }
		[[nodiscard]] constexpr std::uintptr_t getTrampoline() const noexcept
			requires NeedsTrampoline
		{
			return trampoline;
		}
	};
}

#endif
