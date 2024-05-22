#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include "ExecutableMalloc/MemoryManagerAllocator.hpp"

#include <cstdint>
#include <cstring>
#include <memory>
#include <sys/mman.h>

namespace DetourHooking {
	constexpr std::size_t minLength = 5; // The length of an x86-64 near jmp

	enum class Error {
		INSUFFICIENT_LENGTH = 0, // The `instructionLength` was too small
	};

	class Exception : std::exception {
		Error error;
	public:
		explicit Exception(Error error);
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
		static bool writeRelJmp(std::uintptr_t location, std::uintptr_t target, unsigned char* bytes);
#ifdef __x86_64
		static void writeAbsJmp(std::uintptr_t target, unsigned char* bytes);
#endif
	public:
		Hook(
			ExecutableMalloc::MemoryManagerMemoryBlockAllocator& allocator,
			void* original,
			const void* hook,
			std::size_t instructionLength); // May throw exceptions
		void enable() noexcept;
		void disable() noexcept;
		~Hook() noexcept;

		[[nodiscard]] inline bool isEnabled() const noexcept { return enabled; }
		[[nodiscard]] inline std::uintptr_t getTrampoline() const noexcept { return trampoline; }
	};
}

#endif
