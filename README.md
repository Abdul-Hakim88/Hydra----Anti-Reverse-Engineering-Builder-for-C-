# Hydra v3.0


## Overview

C# Code Protector is a Windows tool written in C that instruments a target `.cs` source file with a multi-layered protection class before compiling it. Each build produces a unique binary: class names, method names, and encryption keys are randomised via a seeded LCG so no two outputs share the same symbols.

The project was built iteratively across three versions, each addressing specific weaknesses identified in the previous round.

---

## Techniques Demonstrated

### Static Analysis Resistance
| Technique | Description |
|---|---|
| Symbol randomisation | Every class/method/P-Invoke name is regenerated per build using a seeded LCG |
| PE header erasure | Overwrites the first 8 KB of the loaded module in memory, breaking most PE dumpers |
| UPX LZMA packing | Optional final-stage packing with `--ultra-brute` |
| NativeAOT compilation | Optionally compiles to native machine code — no IL emitted |

### Debugger Detection
| Technique | API / Method |
|---|---|
| WinAPI check | `IsDebuggerPresent()` |
| Remote debugger | `CheckRemoteDebuggerPresent()` |
| NT debug port | `NtQueryInformationProcess` class 7 |
| NtGlobalFlag / PEB heap flags | PEB offset `0x68` (x64) / `0x44` (x86) |
| Hardware breakpoints | Manual CONTEXT struct read, checks DR0–DR3 |
| Timing (OutputDebugString) | Measures tick delta around `OutputDebugString` |
| Kernel debugger | `NtQuerySystemInformation` class `0x23` |
| Managed debugger | `System.Diagnostics.Debugger.IsAttached` |

### Environment Checks
| Technique | Description |
|---|---|
| Process blacklist | 40+ known debuggers, disassemblers, and traffic-analysis tools |
| Sandbox DLL detection | Checks for loaded DLLs associated with Cuckoo, Sandboxie, etc. |
| VM detection | Registry keys (VMware, VirtualBox) + NIC MAC-prefix matching |
| Parent process whitelist | Validates parent and rejects known script/debugger launchers |
| Environment variables | Detects Frida, CLR profiler, and WinDbg attach variables |

### Network / MITM Resistance
| Technique | Description |
|---|---|
| Proxy detection | Reads `HKCU\...\Internet Settings`, flags localhost proxies |
| Certificate store scan | Detects known MITM CA certificates (mitmproxy, etc.) |
| SSL pinning framework | `ServicePointManager` callback skeleton for cert-hash pinning |

### Runtime Hardening
| Technique | Description |
|---|---|
| ETW patch | Writes `RET` (`0xC3`) to `ntdll!EtwEventWrite` to silence event tracing |
| Thread hiding | `NtSetInformationThread` with class `0x11` (HideFromDebugger) |
| Code integrity check | Validates PE signature in memory; triggers on zeroed header |
| Watchdog thread | Background thread re-runs core checks every 1.5–4.5 s (randomised) |
| AES-256 key generation | Per-build 32-byte key generated from LCG seed for string encryption |

---

## Build Requirements

| Requirement | Notes |
|---|---|
| Windows 10/11 x64 | P-Invoke calls are Windows-only |
| .NET 8 SDK | `dotnet` must be on `PATH` |
| MSVC or GCC (MinGW) | To compile `c_protector3_hardened.c` itself |
| UPX *(optional)* | Enables final LZMA packing stage |
| VS C++ workload *(optional)* | Required only for NativeAOT output |

---

## How It Works

```
Input .cs file
      │
      ▼
┌─────────────────────────────┐
│  1. Parse & strip usings    │
│  2. Generate random names   │  ← LCG seeded from time + PID + stack addr
│  3. Write guard class       │  ← All protection methods injected here
│  4. Re-attach user source   │
│  5. Patch Main() entry      │  ← GuardClass.Run() inserted as first call
└─────────────────────────────┘
      │
      ▼
 dotnet publish (Release, win-x64, self-contained)
      │
      ▼
 [optional] UPX --lzma --ultra-brute
      │
      ▼
 <project>_protected.exe
```

---

## Version History

### v1.0
- Basic debugger detection (WinAPI, remote, process list, DLL scan, VM check)
- Managed debugger detection, watchdog thread

### v2.0
- Randomised symbol names per build
- NtGlobalFlag / PEB heap-flag check
- Hardware breakpoint detection (DR0–DR3)
- Thread hiding via `NtSetInformationThread`
- ETW patching, PE header anti-dump
- Parent process whitelist, kernel debugger check

### v3.0 *(current)*
- AES-256 per-build key framework for string encryption
- Proxy detection + SSL certificate pinning skeleton
- Suspicious environment variable scan (Frida, CLR profiler, WinDbg)
- Code integrity self-check
- Enhanced parent process validation (path + grandparent)
- Secure string memory wiping after use

---

## References

- *The Art of Unpacking* — Mark Vincent Yason (IBM X-Force)
- *Practical Malware Analysis* — Sikorski & Honig, Chapter 16
- [NtQueryInformationProcess classes](https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/) — Windows Internals
- [Anti-debugging techniques](https://anti-debug.checkpoint.com/) — Check Point Research
- [PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — Microsoft Docs

---

