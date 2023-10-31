#ifndef DETOURHOOKING_HPP
#define DETOURHOOKING_HPP

#include <cstdint>
#include <memory>

namespace DetourHooking {
	constexpr std::size_t minLength = 5; // The length of an x86-64 near jmp

	enum class Error {
		SUCCESS = 0,
		INSUFFICIENT_LENGTH = 1, // The `instructionLength` was too small
		OUT_OF_MEMORY = 2 // Wasn't able to allocate memory
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
		template <typename T, typename R>
		explicit Hook(T original, const R hook, std::size_t instructionLength = minLength) requires std::conjunction_v<std::negation<std::is_same<T, void*>>, std::negation<std::is_same<R, const void*>>>
			: Hook(reinterpret_cast<void*>(original), reinterpret_cast<const void*>(hook), instructionLength)
		{
		}
		explicit Hook(void* original, const void* hook, std::size_t instructionLength = minLength);
		void enable();
		void disable();
		~Hook();

		[[nodiscard]] inline bool isEnabled() const { return enabled; }
		[[nodiscard]] inline void* getTrampoline() const { return trampoline; }
		[[nodiscard]] inline Error getError() const { return error; }
	};

	class RefCountedHook : public Hook {
		std::int64_t referenceCounter = 0; // This can also be negative

		using Hook::enable;
		using Hook::disable;

	public:
		using Hook::Hook;

		void acquire();
		void release();

		[[nodiscard]] std::int64_t getReferenceCounter() const { return referenceCounter; }
	};
}

#endif
