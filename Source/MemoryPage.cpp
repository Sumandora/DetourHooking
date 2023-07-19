#include "MemoryPage.hpp"

#include "Utils.hpp"

#include <algorithm>
#include <sys/mman.h>

using namespace DetourHooking;

std::vector<MemoryPage> DetourHooking::pages;

void* DetourHooking::FindUnusedMemory(const void* const preferredLocation)
{
	for (std::size_t offset = 0; offset <= relJmpDistance; offset += GetPageSize())
		for (int sign = -1; sign <= 2; sign += 2) {
			void* pointer = mmap(
				reinterpret_cast<char*>(Align(preferredLocation, GetPageSize())) + offset * sign,
				GetPageSize(),
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
				-1,
				0);
			if (pointer != MAP_FAILED)
				return pointer;
		}
	return nullptr;
}

MemoryPage* DetourHooking::FindMemory(const void* const preferredLocation, const std::size_t instructionLength)
{
	for (MemoryPage& memoryPage : pages) { // Loop over memory pages and see if we have one that has enough space to cover all instructions
		const uint64_t distance = PointerDistance(memoryPage.location, preferredLocation);
		if (GetPageSize() - memoryPage.offset >= instructionLength + relJmpLength
#ifdef __x86_64
				+ (distance > relJmpDistance ? absJmpLength : 0)
#endif
		)
			if (distance <= relJmpDistance) {
				// We used this one before, it should be read-only
				Protect(memoryPage.location, GetPageSize(), PROT_READ | PROT_WRITE | PROT_EXEC);
				return &memoryPage;
			}
	}

	void* newLocation = FindUnusedMemory(preferredLocation);

	if (!newLocation)
		return nullptr;

	if (PointerDistance(newLocation, preferredLocation) > relJmpDistance) { // This should never fail, but leave it here just in case
		munmap(newLocation, GetPageSize());
		return nullptr;
	}

	return &pages.emplace_back(MemoryPage{ newLocation, 0, 0 });
}

void DetourHooking::UnmapMemoryPage(MemoryPage* const memoryPage)
{
	munmap(memoryPage->location, GetPageSize());
	std::erase_if(pages, [&memoryPage](const MemoryPage& otherMemoryPage) {
		return memoryPage == &otherMemoryPage;
	});
}