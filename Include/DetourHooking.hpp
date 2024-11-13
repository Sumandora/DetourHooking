#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include "ExecutableMalloc.hpp"
#include "ExecutableMalloc/MemoryManagerAllocator.hpp"
#include "MemoryManager/MemoryManager.hpp"

#include <algorithm>
#include <alloca.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <sys/mman.h>
#include <type_traits>
#include <typeinfo>

namespace DetourHooking {
	constexpr std::size_t minLength = 5; // The length of an x86-64 near jmp
	constexpr std::size_t relJmpDistance = std::numeric_limits<std::int32_t>::max();
	constexpr std::size_t relJmpLength = 5; // The length of an x86(-64) relative jmp
	constexpr std::size_t absJmpLength = 12; // The length of an x86-64 absolute jmp

	namespace detail {
		constexpr bool is64Bit = sizeof(void*) == 8;

		constexpr std::uintptr_t align(std::uintptr_t addr, std::size_t alignment)
		{
			return addr - addr % alignment;
		}

		constexpr std::size_t pointerDistance(std::uintptr_t a, std::uintptr_t b)
		{
			return std::max(a, b) - std::min(a, b);
		}

		inline std::int32_t calculateJumpOffset(std::uintptr_t location, std::size_t instructionLength, std::uintptr_t target)
		{
			// Jumps always start at the ip, which has already increased.
			// The theoretical overflow here is a non-issue as creating a hook at the end of the memory range is never going to happen.
			location += instructionLength;

			// Calculation for a relative jmp:
			const std::size_t distance = detail::pointerDistance(target, location);
			if (distance > relJmpDistance)
				throw std::bad_cast{}; // Missing distance check?????

			auto jmpTarget = static_cast<std::int32_t>(distance); // This cast is exactly why absolute jumps are needed sometimes
			if (static_cast<std::size_t>(jmpTarget) != distance) // Is the represented value still the same?
				throw std::bad_cast{}; // Missing distance check?????

			if (location > target) // Will that go backwards?
				jmpTarget *= -1;
			return jmpTarget;
		}

		inline bool writeRelJmp(std::uintptr_t location, std::uintptr_t target, std::uint8_t* bytes)
		{
			std::int32_t jmpTarget = calculateJumpOffset(location, relJmpLength, target);
			bytes[0] = '\xE9';
			std::memcpy(bytes + 1, &jmpTarget, sizeof(std::int32_t));
			return true;
		}

		inline void writeAbsJmp(std::uintptr_t target, std::uint8_t* bytes)
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
		const MemMgr* memoryManager;
		std::unique_ptr<ExecutableMalloc::MemoryRegion> memoryRegion;

		std::uintptr_t original;
		std::uintptr_t hook;

		std::size_t instructionLength;
		std::conditional_t<NeedsTrampoline, std::uintptr_t, std::unique_ptr<std::byte[]>> trampoline;

		bool enabled;

		void writeJmp(std::uintptr_t location, std::uintptr_t target, std::size_t& offset, std::uint8_t* bytes)
		{
			if constexpr (detail::is64Bit) {
				// If the target is too far away then a absolute jump is needed
				const bool needsAbsJmp = detail::pointerDistance(location + relJmpLength, target) > relJmpDistance;
				if (needsAbsJmp) {
					detail::writeAbsJmp(target, bytes);
					offset += absJmpLength;
					return;
				}
			}

			detail::writeRelJmp(location, target, bytes);
			offset += relJmpLength;
			if constexpr (detail::is64Bit) {
				memoryRegion->resize(memoryRegion->getTo() - memoryRegion->getFrom() - (absJmpLength - relJmpLength)); // some bytes can be saved if a relative jump can be/is used
			}
		}

	public:
		// The following functions are laid out like the lifecycle of a typical Hook (constructor + enable + disable + destructor)
		// One is advised to read top-to-bottom

		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			void* original,
			const void* hook,
			std::size_t instructionLength)
			: memoryManager(allocator.getMemoryManager())
			, original(reinterpret_cast<std::uintptr_t>(original))
			, hook(reinterpret_cast<std::uintptr_t>(hook))
			, instructionLength(instructionLength)
		{
			if (instructionLength < minLength) {
				throw std::exception{}; // It's impossible to fit a near jmp
			}

			// Relative jumps can only cover +/- 2 GB, if the target is too far away, a new memory page has to be allocated
			std::size_t regionSize = 0;

			if constexpr (detail::is64Bit) {
				bool needsJmpIndirection = detail::pointerDistance(this->hook, this->original) > relJmpDistance;

				if (needsJmpIndirection)
					// In the case that the region is close enough to the hook, that a relative jump suffices to go from memoryRegion to hook, the region will be shrinked later.
					regionSize += absJmpLength;
			}

			if constexpr (NeedsTrampoline) {
				regionSize += instructionLength; // The stolen bytes
				regionSize += detail::is64Bit ? absJmpLength : relJmpLength; // It is unlikely, but in theory the top of the block is reachable with a relative jmp but the bottom isn't, the block is shrinked later anyways
			}

			if (regionSize > 0) {
				auto* bytes = static_cast<std::uint8_t*>(alloca(regionSize));
				std::size_t offset = 0;

				memoryRegion = allocator.getRegion(this->original, regionSize, MemMgr::RequiresPermissionsForWriting);

				if constexpr (detail::is64Bit) {
					writeJmp(memoryRegion->getFrom(), this->hook, offset, bytes);
				}

				if constexpr (NeedsTrampoline) {
					trampoline = memoryRegion->getFrom() + offset;

					memoryManager->read(this->original, bytes + offset, instructionLength); // Stolen bytes
					offset += instructionLength;

					writeJmp(memoryRegion->getFrom() + offset, this->original + instructionLength, offset, bytes + offset);
				}

				memoryManager->write(memoryRegion->getFrom(), bytes, offset);

				memoryRegion->setWritable(false);
			}

			if constexpr (!NeedsTrampoline) {
				trampoline = std::unique_ptr<std::byte[]>(new std::byte[instructionLength]);

				memoryManager->read(this->original, trampoline.get(), instructionLength); // Stolen bytes
			}

			enabled = false;
		}

		void enable()
		{
			if (enabled)
				return;

			std::uint8_t bytes[relJmpLength];
			while (true) {
				if constexpr (detail::is64Bit) {
					if (memoryRegion) {
						bool needsJmpIndirection = detail::pointerDistance(hook, original) > relJmpDistance;

						if (needsJmpIndirection) {
							detail::writeRelJmp(original, memoryRegion->getFrom(), bytes);
							break;
						}
					}
				}

				detail::writeRelJmp(original, hook, bytes);
				break;
			}

			if constexpr (MemMgr::RequiresPermissionsForWriting) {
				memoryManager->protect(detail::align(original, memoryManager->getPageGranularity()), memoryManager->getPageGranularity(), { true, true, true });
				memoryManager->write(original, bytes, relJmpLength);
				memoryManager->protect(detail::align(original, memoryManager->getPageGranularity()), memoryManager->getPageGranularity(), { true, false, true });
			} else
				memoryManager->write(original, bytes, relJmpLength);

			enabled = true;
		}

		void disable()
		{
			if (!enabled)
				return;
			std::byte bytes[instructionLength];

			if constexpr (NeedsTrampoline) {
				memoryManager->read(trampoline, bytes, instructionLength);
			} else {
				memcpy(bytes, trampoline.get(), instructionLength);
			}

			if constexpr (MemMgr::RequiresPermissionsForWriting) {
				memoryManager->protect(detail::align(original, memoryManager->getPageGranularity()), memoryManager->getPageGranularity(), { true, true, true });
				memoryManager->write(original, bytes, instructionLength);
				memoryManager->protect(detail::align(original, memoryManager->getPageGranularity()), memoryManager->getPageGranularity(), { true, false, true });
			} else
				memoryManager->write(original, bytes, instructionLength);

			enabled = false;
		}

		~Hook()
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
