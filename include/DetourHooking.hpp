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
		void* hook;
		std::size_t instructionLength;

		bool needsAbsoluteJmp;
		void* absJmp;
		struct MemoryPage* memoryPage;

		bool enabled;

	public:
		void* trampoline;

		Error error;

		Hook(void* original, void* hook, std::size_t instructionLength = minLength);
		void Enable();
		void Disable();
		~Hook();
	};
}

#endif
