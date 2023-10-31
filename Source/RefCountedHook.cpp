#include "DetourHooking.hpp"

using namespace DetourHooking;

void RefCountedHook::acquire()
{
	referenceCounter++;
	if(referenceCounter > 0)
		enable();
}

void RefCountedHook::release()
{
	referenceCounter--;
	if(referenceCounter <= 0)
		disable();
}