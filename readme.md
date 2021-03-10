# XeProtect
Encrypt an Xbox 360 XEX2 formated file

### Java

`$ java -jar XeProtect.jar <xex location>`

### C++
Set to linker entry point to `DllMain`
```c++
extern "C" int _CRT_INIT(...);

BYTE XePr[0x10] = {
	0x58, 0x65, 0x50, 0x72,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

#pragma code_seg(push, r1, ".ptext")

bool APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		DWORD dwKey = *reinterpret_cast<PDWORD>(XePr);
		DWORD dwAddress = *reinterpret_cast<PDWORD>(XePr + 0x04);
		DWORD dwLength = *reinterpret_cast<PDWORD>(XePr + 0x08);

		for (DWORD i = dwAddress; i < dwAddress + dwLength; i++) {
			*(PBYTE)i ^= dwKey;
		}
		
		if (_CRT_INIT(hModule, dwReason, lpReserved)) {
			//main code here
			return true;
		}
	}
	return false;
}

#pragma code_seg(pop, r1)
```
