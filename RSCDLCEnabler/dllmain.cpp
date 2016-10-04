#include <windows.h>
#include <string>

#include "d3dx9_42.h"
#include "FindSignature.h"
#include "Patch.h"

DWORD WINAPI MainThread(void*) {	
	void* VerifySignatureOffset = FindPattern(0x01377000, 0x00DDE000, (uint8_t*)"\x55\x89\xE5\x83\xEC\x08\x8B\x47\x14", "xxxxxxxxx");

	if (VerifySignatureOffset) {
		if (!Patch(VerifySignatureOffset, "\xB0\x01\xC3\x90", 4))
			printf("Failed to patch verify_signature!\n");
		else
			printf("Patch verify_signature success!\n");
	} 

	return 0;
}

void Initialize(void) {
	CreateThread(NULL, 0, MainThread, NULL, NULL, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		InitProxy();
		Initialize();
		return TRUE;
	case DLL_PROCESS_DETACH:
		ShutdownProxy();
		return TRUE;
	}
	return TRUE;
}
