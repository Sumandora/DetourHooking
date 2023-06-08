#ifndef DETOURHOOKING_MEMORYPAGE_HPP
#define DETOURHOOKING_MEMORYPAGE_HPP

#include <cstdint>
#include <memory>
#include <vector>

namespace DetourHooking {
	struct MemoryPage {
		void* location;
		std::size_t offset; // How much has been written there?
		int hooks; // This is a "ref counter", which tracks how many hooks are using the page right now
	};

	extern std::vector<MemoryPage> pages;

	void* FindUnusedMemory(const void* preferredLocation);
	MemoryPage* FindMemory(const void* preferredLocation, const std::size_t instructionLength);
	void UnmapMemoryPage(MemoryPage* memoryPage);
}

#endif