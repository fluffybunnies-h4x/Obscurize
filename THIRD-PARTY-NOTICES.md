# Third-Party Notices

Obscurize redistributes and links against third-party components. Those
components are **not** covered by the PolyForm Shield License in `LICENSE`;
each remains under its own terms, reproduced in full below.

Both components below are MIT-licensed, which permits use in proprietary and
commercially licensed products provided the copyright notice and permission
notice are retained. If you redistribute Obscurize in source or binary form,
you must carry this file with it.

| Component | Version / Source | License | Linkage |
|---|---|---|---|
| r77-rootkit | bytecode77, vendored at `r77-rootkit/r77-rootkit-master/` | MIT | Source files compiled into `ObscurizeAgent` |
| Microsoft Detours | Prebuilt `detours.lib`, vendored at `r77-rootkit/r77-rootkit-master/SlnBin/{x86,x64}/` | MIT | Static library linked into `ObscurizeAgent` |

## 1. r77-rootkit

Upstream: <https://github.com/bytecode77/r77-rootkit>

Obscurize compiles the following r77 source files directly into the agent DLL
(see `ObscurizeAgent/ObscurizeAgent-x86.vcxproj` and
`ObscurizeAgent/ObscurizeAgent-x64.vcxproj`):

- `r77api/r77header.c` — PE header marking, used for agent detach on service stop
- `r77api/r77win.c` — Win32 helper routines
- `r77api/peb.c` — PEB walking
- `r77api/clist.c` — list utilities
- `ReflectiveDllMain/ReflectiveDllMain.c` — reflective DLL loader

and includes these headers:

- `r77api/ntdll.h` — NT API typedefs
- `r77api/r77mindef.h` — allocation macros and status helpers
- `r77api/r77win.h`
- `r77api/r77header.h`
- `r77/detours.h`

License text as published by the upstream project:

```
MIT License

Copyright (c) 2025 bytecode77

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Note on the vendored r77 tree

The full upstream r77 tree is vendored in this repository, so files beyond the
ones listed above are present but unused by Obscurize. Two of them are fonts
carried in r77's `$Docs/Fonts/` directory and licensed under the SIL Open Font
License, not MIT:

- `Electrolize-OFL.txt` (Electrolize)
- `OFL-SourceCodePro.txt` (Source Code Pro)

Obscurize does not use, embed, or distribute these fonts as part of any build
output. Their OFL license files travel with them in the vendored tree. Pruning
the vendored tree down to the files actually required by the build would remove
this from the dependency surface entirely.

## 2. Microsoft Detours

Upstream: <https://github.com/microsoft/Detours>

Obscurize links the prebuilt `detours.lib` static libraries taken from r77's
`SlnBin/` directory for userland API hooking in `ObscurizeAgent/Hooks.c`. No
Detours source is modified. Note that the vendored `.lib` files ship without
an accompanying license file; the upstream license text is reproduced here to
satisfy the notice requirement.

```
Copyright (c) Microsoft Corporation

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Windows platform libraries

`ntdll.lib`, `psapi.lib`, `shlwapi.lib`, `iphlpapi.lib`, `advapi32.lib`, and
`ws2_32.lib` are import libraries from the Windows SDK, used under the terms of
the SDK license that accompanies your Visual Studio installation. They are not
redistributed by this project.
