#ifndef DETOURHOOKING_MEMORYPAGE_HPP
#define DETOURHOOKING_MEMORYPAGE_HPP

#include <cstdint>
#include <memory>
#include <vector>

namespace DetourHooking {
	struct MemoryPage {
		void* location;
		std::size_t offset = 0; // How much has been written there?
		inline explicit MemoryPage(void* location) : location(location) {}
		~MemoryPage();
	};

	extern std::vector<std::shared_ptr<MemoryPage>> pages;

	[[nodiscard]] void* findUnusedMemory(const void* preferredLocation);
	[[nodiscard]] std::shared_ptr<MemoryPage> findMemory(const void* preferredLocation, std::size_t instructionLength);
	void unmapMemoryPage(const std::shared_ptr<MemoryPage>& memoryPage);
}

#endif