#include "MemoryPage.hpp"

#include "Utils.hpp"

#include <sys/mman.h>

using namespace DetourHooking;

std::vector<std::shared_ptr<MemoryPage>> DetourHooking::pages;

MemoryPage::~MemoryPage()
{
	munmap(location, getPageSize());
}

void* DetourHooking::findUnusedMemory(const void* const preferredLocation)
{
	for (std::size_t offset = 0; offset <= relJmpDistance; offset += getPageSize())
		for (int sign = -1; sign <= 2; sign += 2) {
			void* pointer = mmap(
				reinterpret_cast<char*>(align(preferredLocation, getPageSize())) + offset * sign,
				getPageSize(),
				PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
				-1,
				0);
			if (pointer != MAP_FAILED)
				return pointer;
		}
	return nullptr;
}

std::shared_ptr<MemoryPage> DetourHooking::findMemory(const void* const preferredLocation, const std::size_t instructionLength)
{
	for (const std::shared_ptr<MemoryPage>& memoryPage : pages) { // Loop over memory pages and see if we have one that has enough space to cover all instructions
		const uint64_t distance = pointerDistance(memoryPage->location, preferredLocation);
		if (getPageSize() - memoryPage->offset >= instructionLength + relJmpLength
#ifdef __x86_64
				+ (distance > relJmpDistance ? absJmpLength : 0)
#endif
		)
			if (distance <= relJmpDistance)
				return memoryPage;
	}

	void* newLocation = findUnusedMemory(preferredLocation);

	if (!newLocation)
		return nullptr;

	if (pointerDistance(newLocation, preferredLocation) > relJmpDistance) { // This should never fail, but leave it here just in case
		munmap(newLocation, getPageSize());
		return nullptr;
	}

	return pages.emplace_back(std::make_shared<MemoryPage>(newLocation));
}

void DetourHooking::unmapMemoryPage(const std::shared_ptr<MemoryPage>& memoryPage)
{
	if(!memoryPage.unique())
		return; // There are other references than the vector, we shouldn't release this one yet
	std::erase_if(pages, [&memoryPage](const std::shared_ptr<MemoryPage>& otherMemoryPage) {
		// Are the underlying pointers the same?
		return memoryPage.get() == otherMemoryPage.get();
	});
	// The vector should hold the last valid reference, by destroying it we invoke the destructor, which unmaps the memory
}