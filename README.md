# Detour Hooking Library

This is a lightweight and efficient library for detour hooking for Linux. It allows you to redirect the execution flow
to your function before or after the original function is called.

## Usage

To hook a function, create a `Hook` object and pass the address of the original function, the address of your own
function, and the size of the stolen bytes. The stolen bytes size is the number of bytes that will be overwritten with a
jump to your own function. In case you want to dynamically find this at runtime I recommend
a [length disassembler](https://en.wikipedia.org/wiki/Disassembler#Length_disassembler).

One can opt to disable the creation of a trampoline to save executable memory by setting `NeedsTrampoline` to false.

To minimize memory usage, the library reuses memory pages whenever possible. When you create a new hook, it will try to
find a suitable location in memory to store the stolen bytes and the jump instruction. If no suitable location is found,
it will allocate a new memory page.

You can find an example in the Example sub-directory.
