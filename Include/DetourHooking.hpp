#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include <cstdint>

namespace DetourHooking {
	constexpr std::size_t minLength = 5; // The length of an x86-64 near jmp

	enum class Error {
		SUCCESS = 0,
		INSUFFICIENT_LENGTH = 1,
		OUT_OF_MEMORY = 2
	};

	class Hook {
	private:
		void* original;
		const void* hook;
		std::size_t instructionLength;

#ifdef __x86_64
		bool needsAbsoluteJmp;
		void* absJmp;
#endif
		struct MemoryPage* memoryPage;

		bool enabled;

	public:
		void* trampoline;

		Error error;

		Hook(void* const original, const void* const hook, std::size_t instructionLength = minLength);
		void enable();
		void disable();
		~Hook();
	};
}

#endif
