#ifndef DETOURHOOKING
#define DETOURHOOKING

#include <optional>

#define DETOURHOOKING_MIN_LENGTH 5 // The length of an x86-64 near jmp

// Error definitions
#define DETOURHOOKING_SUCCESS 0
#define DETOURHOOKING_INSUFFICIENT_LENGTH 1
#define DETOURHOOKING_OUT_OF_MEMORY 2

class Hook {
private:
	void* original;
	void* hook;
	size_t instructionLength;

	bool needsAbsoluteJmp;
	void* absJmp;

public:
	void* trampoline;

	int error;

	Hook(void* original, void* hook, size_t instructionLength = DETOURHOOKING_MIN_LENGTH);
	void Enable();
	void Disable();
};

#endif
