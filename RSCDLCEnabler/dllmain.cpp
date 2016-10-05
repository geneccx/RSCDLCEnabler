#include <windows.h>
#include <string>

#include "d3dx9_42.h"
#include "FindSignature.h"
#include "Patch.h"

DWORD WINAPI MainThread(void*) {	
	uint8_t* VerifySignatureOffset = FindPattern(0x01377000, 0x00DDE000, (uint8_t*)"\xE8\x00\x00\x00\x00\x83\xC4\x20\x88\xC3", "x????xxxxx");

	if (VerifySignatureOffset) {
		if (!Patch(VerifySignatureOffset + 8, "\xB3\x01", 2))
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
