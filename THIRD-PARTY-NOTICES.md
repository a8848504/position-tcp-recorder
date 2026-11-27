# Third-party components

The MIT license covers this tool's source code, not the bundled third-party programs.

- Wireshark 4.6.9 (tshark, dumpcap, mergecap and their runtime dependencies): GPL-2.0-or-later and the licenses of the included libraries. Official source: https://www.wireshark.org/ . The complete corresponding Wireshark source archive and original COPYING are included in each full portable release. These are separate executables invoked by this application.
- Microsoft etl2pcapng 1.11.0: MIT. Source: https://github.com/microsoft/etl2pcapng . Source and license are included in the full release.
- golang.org/x/sys: BSD-3-Clause. https://go.googlesource.com/sys/ . Version is pinned in go.mod and go.sum.
- Go runtime and standard library: BSD-3-Clause. https://go.dev/LICENSE .
- github.com/akavel/rsrc: MIT, build tool only. https://github.com/akavel/rsrc .

Windows system components are provided by Windows. Npcap and its driver are not redistributed. The full portable ZIP and matching third-party sources are available beside the standalone EXE in every GitHub Release. Redistribution must retain the applicable notices and corresponding source requirements.
