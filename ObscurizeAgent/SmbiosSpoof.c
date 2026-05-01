#include "SmbiosSpoof.h"
#include "Config.h"
#include "../ObscurizeShared/ObscurizeDef.h"

// ============================================================
//  ObscurizeAgent – SmbiosSpoof.c
//
//  Rebuilds a raw RSMB buffer (GetSystemFirmwareTable 'RSMB')
//  with spoofed BIOS and system-info strings so that WMI and
//  any process that calls GetSystemFirmwareTable directly sees
//  the values appropriate for the current Obscurize mode.
//
//  SMBIOS structures patched:
//
//    Type 0  (BIOS Information)
//      Offset 4  Vendor string index
//      Offset 5  BIOS Version string index
//      Offset 8  BIOS Release Date string index
//
//    Type 1  (System Information)
//      Offset 4  Manufacturer string index
//      Offset 5  Product Name string index
//      Offset 7  Serial Number string index  (Win32_BIOS.SerialNumber)
//
//  String replacement strategy:
//    Rather than patching in-place (which constrains string
//    length), the function walks every structure in the input
//    table and rebuilds it into a fresh heap buffer, replacing
//    the target strings as it goes.  The output Length field
//    in the RSMB header is updated accordingly.
// ============================================================

// ── ANSI spoof strings ────────────────────────────────────────
// SMBIOS string tables are ASCII; the wide literals in
// ObscurizeDef.h are not usable here.

// Defensive mode  →  host looks like a VMware VM
static const char s_DefBiosVendor[]   = "Phoenix Technologies LTD";
static const char s_DefBiosVersion[]  = "6.00";
static const char s_DefBiosDate[]     = "07/02/2015";
static const char s_DefManufacturer[] = "VMware, Inc.";
static const char s_DefProduct[]      = "VMware Virtual Platform";

// Trap mode  →  VM looks like a real Dell workstation
static const char s_TrapBiosVendor[]      = "Dell Inc.";
static const char s_TrapBiosVersion[]     = "1.22.0";
static const char s_TrapBiosDate[]        = "04/14/2023";
static const char s_TrapManufacturer[]    = "Dell Inc.";
static const char s_TrapProduct[]         = "Precision 5560";
static const char s_TrapSerialNumber[]    = "7X8K9P2";

// Defensive mode serial (typical VMware VM value; matches PatchWmicOutput)
static const char s_DefSerialNumber[]     = "None";

// Maximum strings tracked per SMBIOS structure.
// The SMBIOS spec allows up to 255 strings per structure;
// in practice BIOS and system structures have far fewer.
#define MAX_SMBIOS_STRINGS  32

// ── RSMB header ───────────────────────────────────────────────
// The buffer returned by GetSystemFirmwareTable('RSMB', 0, ...)
// begins with this 8-byte header, followed by Length bytes of
// raw SMBIOS table data.

#pragma pack(push, 1)
typedef struct _RSMB_HEADER
{
    BYTE  Used20CallingMethod;
    BYTE  SMBIOSMajorVersion;
    BYTE  SMBIOSMinorVersion;
    BYTE  DmiRevision;
    DWORD Length;           // Byte count of SMBIOS table that follows
} RSMB_HEADER;              // 8 bytes total
#pragma pack(pop)

// ── Internal helpers ──────────────────────────────────────────

// Advance past the string section (delimited by \0\0).
// Returns a pointer to the first byte of the NEXT structure.
static LPCBYTE SkipStringSection(LPCBYTE p, LPCBYTE tableEnd)
{
    while (p < tableEnd)
    {
        if (*p == '\0')
        {
            // Two consecutive nulls mark the end of the section.
            if (p + 1 < tableEnd && *(p + 1) == '\0')
                return p + 2;
            p++;    // Single null = end of one string; keep scanning.
        }
        else
        {
            p++;
        }
    }
    return tableEnd;
}

// Collect 0-based pointers to each string in the string section.
// Returns the number of strings found (≤ maxStrings).
static DWORD CollectStrings(LPCBYTE strSection, LPCBYTE tableEnd,
                             LPCSTR  strings[],  DWORD   maxStrings)
{
    DWORD   count = 0;
    LPCBYTE p     = strSection;

    while (p < tableEnd && *p != '\0')
    {
        if (count < maxStrings)
            strings[count] = (LPCSTR)p;
        count++;

        // Advance to end of this string.
        while (p < tableEnd && *p != '\0')
            p++;
        p++;    // Skip null terminator.
    }
    return count;
}

// Write a string section to out, substituting strings whose
// 0-based index has a non-NULL entry in replaceMap.
// Always writes a valid double-null terminator.
// Returns the number of bytes written.
static DWORD WriteStringSection(LPBYTE  out,
                                 LPCSTR  strings[],
                                 DWORD   strCount,
                                 LPCSTR  replaceMap[])
{
    LPBYTE p = out;

    if (strCount == 0)
    {
        // Empty string section: mandatory \0\0.
        *p++ = '\0';
        *p++ = '\0';
    }
    else
    {
        for (DWORD i = 0; i < strCount; i++)
        {
            LPCSTR s   = (replaceMap[i] != NULL) ? replaceMap[i] : strings[i];
            SIZE_T len = lstrlenA(s);
            CopyMemory(p, s, len + 1);  // +1 for null terminator
            p += len + 1;
        }
        *p++ = '\0';    // Extra null → forms double-null at end.
    }

    return (DWORD)(p - out);
}

// ── Public API ────────────────────────────────────────────────

LPBYTE PatchRSMBBuffer(LPCBYTE original, DWORD originalSize, LPDWORD pOutPatchedSize)
{
    if (!original || !pOutPatchedSize || originalSize < sizeof(RSMB_HEADER))
        return NULL;

    const RSMB_HEADER *hdr = (const RSMB_HEADER *)original;
    if (originalSize < sizeof(RSMB_HEADER) + hdr->Length)
        return NULL;

    // Select spoof strings for the current mode.
    DWORD mode = ObsGetMode();

    const char *spoofBiosVendor    = (mode == OBS_MODE_TRAP) ? s_TrapBiosVendor    : s_DefBiosVendor;
    const char *spoofBiosVersion   = (mode == OBS_MODE_TRAP) ? s_TrapBiosVersion   : s_DefBiosVersion;
    const char *spoofBiosDate      = (mode == OBS_MODE_TRAP) ? s_TrapBiosDate      : s_DefBiosDate;
    const char *spoofManufacturer  = (mode == OBS_MODE_TRAP) ? s_TrapManufacturer  : s_DefManufacturer;
    const char *spoofProduct       = (mode == OBS_MODE_TRAP) ? s_TrapProduct       : s_DefProduct;
    const char *spoofSerialNumber  = (mode == OBS_MODE_TRAP) ? s_TrapSerialNumber  : s_DefSerialNumber;

    // Allocate output buffer: original size + headroom for string growth.
    DWORD  outBufCap = originalSize + OBS_SMBIOS_HEADROOM;
    LPBYTE outBuf    = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outBufCap);
    if (!outBuf) return NULL;

    // Copy RSMB header; Length will be updated at the end.
    CopyMemory(outBuf, original, sizeof(RSMB_HEADER));

    LPBYTE  outPtr = outBuf + sizeof(RSMB_HEADER);
    LPCBYTE inPtr  = original + sizeof(RSMB_HEADER);
    LPCBYTE inEnd  = inPtr + hdr->Length;

    while (inPtr < inEnd)
    {
        // Minimum valid structure: 4-byte header (Type, Length, Handle).
        if (inPtr + 4 > inEnd) break;

        BYTE structType = inPtr[0];
        BYTE structLen  = inPtr[1];

        // Sanity: formatted area must be ≥ 4 bytes and fit within the table.
        if (structLen < 4 || inPtr + structLen > inEnd) break;

        // Locate the string section and find the next structure.
        LPCBYTE strSection = inPtr + structLen;
        LPCBYTE nextStruct = SkipStringSection(strSection, inEnd);

        // For structures we don't modify, copy raw bytes verbatim to avoid
        // the MAX_SMBIOS_STRINGS overflow crash in WriteStringSection.
        if (structType != 0 && structType != 1)
        {
            SIZE_T rawSize = (SIZE_T)(nextStruct - inPtr);
            if (outPtr + rawSize > outBuf + outBufCap) goto fail;
            CopyMemory(outPtr, inPtr, rawSize);
            outPtr += rawSize;
            if (structType == 127) break;
            inPtr = nextStruct;
            continue;
        }

        // Collect all strings from this structure (0-based).
        LPCSTR strings[MAX_SMBIOS_STRINGS]   = { NULL };
        LPCSTR replaceMap[MAX_SMBIOS_STRINGS] = { NULL };
        DWORD  strCount = CollectStrings(strSection, nextStruct,
                                         strings, MAX_SMBIOS_STRINGS);
        if (strCount > MAX_SMBIOS_STRINGS) strCount = MAX_SMBIOS_STRINGS;

        // ── Type 0: BIOS Information ─────────────────────────
        // Offset 4  Vendor string index  (1-based)
        // Offset 5  BIOS Version string index
        // Offset 8  BIOS Release Date string index
        if (structType == 0 && structLen >= 9)
        {
            BYTE vi = inPtr[4];   // Vendor
            BYTE bi = inPtr[5];   // BIOS Version
            BYTE di = inPtr[8];   // Release Date

            if (vi > 0 && vi <= strCount) replaceMap[vi - 1] = spoofBiosVendor;
            if (bi > 0 && bi <= strCount) replaceMap[bi - 1] = spoofBiosVersion;
            if (di > 0 && di <= strCount) replaceMap[di - 1] = spoofBiosDate;
        }

        // ── Type 1: System Information ───────────────────────
        // Offset 4  Manufacturer string index  (1-based)
        // Offset 5  Product Name string index
        // Offset 7  Serial Number string index  ← Win32_BIOS.SerialNumber
        else if (structType == 1 && structLen >= 8)
        {
            BYTE mi = inPtr[4];   // Manufacturer
            BYTE pi = inPtr[5];   // Product Name
            BYTE si = inPtr[7];   // Serial Number

            if (mi > 0 && mi <= strCount) replaceMap[mi - 1] = spoofManufacturer;
            if (pi > 0 && pi <= strCount) replaceMap[pi - 1] = spoofProduct;
            if (si > 0 && si <= strCount) replaceMap[si - 1] = spoofSerialNumber;
        }

        // Guard: ensure we won't overrun the output buffer.
        // The headroom is 256 bytes; a single structure's string-section
        // growth is at most ~30 bytes, so this check is very conservative.
        if (outPtr + structLen + (DWORD)(nextStruct - strSection) + 64
                > outBuf + outBufCap)
        {
            goto fail;
        }

        // Write the formatted area unchanged (string indices stay valid).
        CopyMemory(outPtr, inPtr, structLen);
        outPtr += structLen;

        // Write the string section, substituting replacement strings.
        outPtr += WriteStringSection(outPtr, strings, strCount, replaceMap);

        // Type 127 = End-of-Table marker; stop after writing it.
        if (structType == 127) break;

        inPtr = nextStruct;
    }

    // Update the RSMB header Length field to reflect the new table size.
    DWORD newTableLen = (DWORD)(outPtr - (outBuf + sizeof(RSMB_HEADER)));
    ((RSMB_HEADER *)outBuf)->Length = newTableLen;

    *pOutPatchedSize = (DWORD)(outPtr - outBuf);
    return outBuf;

fail:
    HeapFree(GetProcessHeap(), 0, outBuf);
    return NULL;
}
