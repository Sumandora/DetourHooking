# Detour Hooking Library

This is a lightweight and efficient library for detour hooking for Linux. It allows you to redirect the execution flow
to your function before or after the original function is called.

## Usage

To hook a function, create a `Hook` object and pass the address of the original function, the address of your own
function, and the size of the stolen bytes. The stolen bytes size is the number of bytes that will be overwritten with a
jump to your own function. In case you want to dynamically find this at runtime I recommend
a [length disassembler](https://en.wikipedia.org/wiki/Disassembler#Length_disassembler).

```c++
Hook* hook = new Hook(OriginalFunction, MyFunction, StolenBytesSize);
```

After creating the `Hook` object, enable it by calling the `enable()` method.

```c++
hook->enable();
```

If the hook was successfully enabled, the `error` member of the `Hook` object will be set to `DETOURHOOKING_SUCCESS`.
You can check this by using an assertion:

```c++
assert(hook->error == DETOURHOOKING_SUCCESS);
```

In case you want to disable the `Hook` you can use the `disable()` method

```c++
hook->disable();
```

To minimize memory usage, the library reuses memory pages whenever possible. When you create a new hook, it will try to
find a suitable location in memory to store the stolen bytes and the jump instruction. If no suitable location is found,
it will allocate a new memory page.

## Example

Here's a simple example that hooks the `puts` function and adds a prefix to the output:

```c++
#include "DetourHooking.hpp"

using namespace DetourHooking;

#include <cstdio>
#include <cstdarg>
#include <cassert>

int MyPuts(const char *__s)
{
	return printf("I can confirm this: %s", __s);
}

int main()
{
	Hook* hook = new Hook((void*)puts, (void*) MyPuts, /* The stolen bytes size will vary for each system */);
	hook->enable();
	assert(hook->error == DETOURHOOKING_SUCCESS);

	puts("Detour Hooking is awesome\n");

	return 0;
}
```

Another example can be found in the Example subdirectory

## Credits

- ChatGPT for writing large parts of this readme ^^
