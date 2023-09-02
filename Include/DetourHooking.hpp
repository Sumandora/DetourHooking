#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include <cstdint>
#include <memory>

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
		std::shared_ptr<struct MemoryPage> memoryPage;

		bool enabled;

		void* trampoline;
		Error error;

	public:

		Hook(void* original, const void* hook, std::size_t instructionLength = minLength);
		void enable();
		void disable();
		~Hook();

		[[nodiscard]] inline bool isEnabled() const { return enabled; }
		[[nodiscard]] inline void* getTrampoline() const { return trampoline; }
		[[nodiscard]] inline Error getError() const { return error; }
	};
}

#endif
