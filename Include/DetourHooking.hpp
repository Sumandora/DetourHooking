#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include "ExecutableMalloc.hpp"
#include "ExecutableMalloc/MemoryManagerAllocator.hpp"
#include "LengthDisassembler/LengthDisassembler.hpp"
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
#include <utility>

namespace DetourHooking {
	constexpr std::size_t MIN_LENGTH = 5; // The length of a x86-64 near jump
	constexpr std::size_t REL_JMP_DISTANCE = std::numeric_limits<std::int32_t>::max();
	constexpr std::size_t REL_JMP_LENGTH = 5; // The length of a x86(-64) relative jump
	constexpr std::size_t ABS_JMP_LENGTH = 12; // The length of a x86-64 absolute jump

	namespace detail {
		constexpr bool IS_64_BIT = sizeof(void*) == 8;
		constexpr LengthDisassembler::MachineMode DEFAULT_MACHINE_MODE = detail::IS_64_BIT
			? LengthDisassembler::MachineMode::LONG_MODE
			: LengthDisassembler::MachineMode::LONG_COMPATIBILITY_MODE;

		constexpr std::uintptr_t align(std::uintptr_t addr, std::size_t alignment)
		{
			return addr - addr % alignment;
		}

		constexpr std::size_t pointer_distance(std::uintptr_t a, std::uintptr_t b)
		{
			return std::max(a, b) - std::min(a, b);
		}

		inline std::int32_t calculate_jump_offset(std::uintptr_t location, std::size_t instruction_length, std::uintptr_t target)
		{
			// Jumps always start at the instruction pointer, which has already increased.
			// The theoretical overflow here is a non-issue as creating a hook at the end of the memory range is never going to happen.
			location += instruction_length;

			// Calculation for a relative jump:
			const std::size_t distance = detail::pointer_distance(target, location);
			if (distance > REL_JMP_DISTANCE)
				throw std::bad_cast{}; // Missing distance check?????

			auto jmp_target = static_cast<std::int32_t>(distance); // This cast is exactly why absolute jumps are needed sometimes
			if (std::cmp_not_equal(jmp_target, distance)) // Is the represented value still the same?
				throw std::bad_cast{}; // Missing distance check?????

			if (location > target) // Will that go backwards?
				jmp_target *= -1;
			return jmp_target;
		}

		inline bool write_rel_jmp(std::uintptr_t location, std::uintptr_t target, std::uint8_t* bytes)
		{
			std::int32_t jmp_target = calculate_jump_offset(location, REL_JMP_LENGTH, target);
			bytes[0] = '\xE9';
			std::memcpy(bytes + 1, &jmp_target, sizeof(std::int32_t));
			return true;
		}

		inline void write_abs_jmp(std::uintptr_t target, std::uint8_t* bytes)
		{
			bytes[0] = '\x48';
			bytes[1] = '\xB8';
			std::memcpy(bytes + 2, &target, sizeof(void*));
			bytes[10] = '\xFF';
			bytes[11] = '\xE0';
		}
	}

	template <bool NeedsTrampoline, typename MemMgr>
		requires MemoryManager::Reader<MemMgr> && MemoryManager::Writer<MemMgr> && (!MemMgr::REQUIRES_PERMISSIONS_FOR_WRITING || MemoryManager::Protector<MemMgr>)
	class Hook {
		const MemMgr* memory_manager;
		std::unique_ptr<ExecutableMalloc::MemoryRegion> memory_region;

		std::uintptr_t original;
		std::uintptr_t hook;

		std::size_t stolen_bytes_count;
		std::conditional_t<NeedsTrampoline, std::uintptr_t, std::unique_ptr<std::byte[]>> trampoline;

		bool enabled;

		void write_jmp(std::uintptr_t location, std::uintptr_t target, std::size_t& offset, std::uint8_t* bytes)
		{
			if constexpr (detail::IS_64_BIT) {
				// If the target is too far away, then an absolute jump is needed
				const bool needs_abs_jmp = detail::pointer_distance(location + REL_JMP_LENGTH, target) > REL_JMP_DISTANCE;
				if (needs_abs_jmp) {
					detail::write_abs_jmp(target, bytes);
					offset += ABS_JMP_LENGTH;
					return;
				}
			}

			detail::write_rel_jmp(location, target, bytes);
			offset += REL_JMP_LENGTH;
			if constexpr (detail::IS_64_BIT) {
				memory_region->resize(memory_region->get_to() - memory_region->get_from() - (ABS_JMP_LENGTH - REL_JMP_LENGTH)); // Some bytes can be saved if a relative jump can be/is used
			}
		}

		static std::size_t get_stolen_bytes_count(const MemMgr* mem_mgr, std::uintptr_t address, LengthDisassembler::MachineMode machine_mode)
		{
			std::byte buffer[15]{};
			mem_mgr->read(address, buffer, sizeof(buffer));

			std::size_t len = 0;
			while (len <= MIN_LENGTH) {
				auto insn = LengthDisassembler::disassemble(buffer + len, machine_mode, sizeof(buffer));
				len += insn.value().length;
			}
			return len;
		}

	public:
		// The following functions are laid out like the life-cycle of a typical Hook (constructor + enable + disable + destructor)
		// One is advised to read top-to-bottom

		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			std::uintptr_t original,
			std::uintptr_t hook,
			std::size_t stolen_bytes_count)
			: memory_manager(allocator.get_memory_manager())
			, original(original)
			, hook(hook)
			, stolen_bytes_count(stolen_bytes_count)
		{
			if (stolen_bytes_count < MIN_LENGTH) {
				throw std::exception{}; // It's impossible to fit a near jump
			}

			// Relative jumps can only cover +/- 2 GB, if the target is too far away, a new memory page has to be allocated
			std::size_t region_size = 0;

			if constexpr (detail::IS_64_BIT) {
				bool needs_jmp_indirection = detail::pointer_distance(this->hook, this->original) > REL_JMP_DISTANCE;

				if (needs_jmp_indirection)
					// In the case that the region is close enough to the hook, that a relative jump suffices to go from memory_region to hook, the region will be shrinked later.
					region_size += ABS_JMP_LENGTH;
			}

			if constexpr (NeedsTrampoline) {
				region_size += stolen_bytes_count; // The stolen bytes
				region_size += detail::IS_64_BIT ? ABS_JMP_LENGTH : REL_JMP_LENGTH; // It is unlikely, but in theory the top of the block is reachable with a relative jump but the bottom isn't, the block is shrinked later anyways
			}

			if (region_size > 0) {
				auto* bytes = static_cast<std::uint8_t*>(alloca(region_size));
				std::size_t offset = 0;

				memory_region = allocator.get_region(this->original, region_size, MemMgr::REQUIRES_PERMISSIONS_FOR_WRITING);

				if constexpr (detail::IS_64_BIT) {
					write_jmp(memory_region->get_from(), this->hook, offset, bytes);
				}

				if constexpr (NeedsTrampoline) {
					trampoline = memory_region->get_from() + offset;

					memory_manager->read(this->original, bytes + offset, stolen_bytes_count); // Stolen bytes
					offset += stolen_bytes_count;

					write_jmp(memory_region->get_from() + offset, this->original + stolen_bytes_count, offset, bytes + offset);
				}

				memory_manager->write(memory_region->get_from(), bytes, offset);

				memory_region->set_writable(false);
			}

			if constexpr (!NeedsTrampoline) {
				trampoline = std::unique_ptr<std::byte[]>(new std::byte[stolen_bytes_count]);

				memory_manager->read(this->original, trampoline.get(), stolen_bytes_count); // Stolen bytes
			}

			enabled = false;
		}

		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			std::uintptr_t original,
			std::uintptr_t hook,
			LengthDisassembler::MachineMode machine_mode = detail::DEFAULT_MACHINE_MODE)
			: Hook(allocator, original, hook, get_stolen_bytes_count(allocator.get_memory_manager(), original, machine_mode))
		{
		}

		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			void* original,
			const void* hook,
			std::size_t stolen_bytes_count)
			requires(MemoryManager::LocalAware<MemMgr> && MemMgr::IS_LOCAL)
			: Hook(
				  allocator,
				  reinterpret_cast<std::uintptr_t>(original),
				  reinterpret_cast<std::uintptr_t>(hook),
				  stolen_bytes_count)
		{
		}

		Hook(
			ExecutableMalloc::MemoryManagerAllocator<MemMgr>& allocator,
			void* original,
			const void* hook,
			LengthDisassembler::MachineMode machine_mode = detail::DEFAULT_MACHINE_MODE)
			requires(MemoryManager::LocalAware<MemMgr> && MemMgr::IS_LOCAL)
			: Hook(
				  allocator,
				  reinterpret_cast<std::uintptr_t>(original),
				  reinterpret_cast<std::uintptr_t>(hook),
				  machine_mode)
		{
		}

		void enable()
		{
			if (enabled)
				return;

			auto* bytes = static_cast<std::uint8_t*>(alloca(REL_JMP_LENGTH));
			while (true) {
				if constexpr (detail::IS_64_BIT) {
					if (memory_region) {
						bool needs_jmp_indirection = detail::pointer_distance(hook, original) > REL_JMP_DISTANCE;

						if (needs_jmp_indirection) {
							detail::write_rel_jmp(original, memory_region->get_from(), bytes);
							break;
						}
					}
				}

				detail::write_rel_jmp(original, hook, bytes);
				break;
			}

			if constexpr (MemMgr::REQUIRES_PERMISSIONS_FOR_WRITING) {
				memory_manager->protect(detail::align(original, memory_manager->get_page_granularity()), memory_manager->get_page_granularity(), { true, true, true });
				memory_manager->write(original, bytes, REL_JMP_LENGTH);
				memory_manager->protect(detail::align(original, memory_manager->get_page_granularity()), memory_manager->get_page_granularity(), { true, false, true });
			} else
				memory_manager->write(original, bytes, REL_JMP_LENGTH);

			enabled = true;
		}

		void disable()
		{
			if (!enabled)
				return;
			auto* bytes = static_cast<std::uint8_t*>(alloca(stolen_bytes_count));

			if constexpr (NeedsTrampoline) {
				memory_manager->read(trampoline, bytes, stolen_bytes_count);
			} else {
				memcpy(bytes, trampoline.get(), stolen_bytes_count);
			}

			if constexpr (MemMgr::REQUIRES_PERMISSIONS_FOR_WRITING) {
				memory_manager->protect(detail::align(original, memory_manager->get_page_granularity()), memory_manager->get_page_granularity(), { true, true, true });
				memory_manager->write(original, bytes, stolen_bytes_count);
				memory_manager->protect(detail::align(original, memory_manager->get_page_granularity()), memory_manager->get_page_granularity(), { true, false, true });
			} else
				memory_manager->write(original, bytes, stolen_bytes_count);

			enabled = false;
		}

		~Hook()
		{
			if (enabled)
				disable();
		}

		[[nodiscard]] constexpr bool is_enabled() const noexcept { return enabled; }
		[[nodiscard]] constexpr std::uintptr_t get_trampoline() const noexcept
			requires NeedsTrampoline
		{
			return trampoline;
		}
	};
}

#endif
