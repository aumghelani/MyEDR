# MyEDR

An educational Windows Endpoint Detection and Response (EDR) prototype: a WDM kernel driver that collects process, thread, image-load, registry and handle telemetry, plus a user-mode console that displays it.

## Overview

MyEDR is a learning project for Windows kernel internals and detection engineering. The driver subscribes to documented kernel notification callbacks (no kernel patching or hooking), turns interesting observations into flat `EDR_EVENT` records, and stores them in a spinlock-protected ring buffer. The console client opens the driver's device and drains events over an IOCTL, printing each one with a severity tag.

Each detection maps to a MITRE ATT&CK technique. The heuristics are deliberately simple, and the project is an early-stage prototype, not a production security product. See [Known Issues](#known-issues) before building or loading it.

> Kernel bugs crash the whole machine. Only load this driver in a disposable Windows test VM with snapshots.

## Key Features

| Event | Kernel mechanism | Heuristic | ATT&CK |
|---|---|---|---|
| Process create / exit | `PsSetCreateProcessNotifyRoutineEx` | Logs every create and exit; flags **PPID spoofing** when the claimed parent PID differs from the process that actually issued the create | T1134.004 |
| Remote thread | `PsSetCreateThreadNotifyRoutine` | Flags a thread created in a process by a different process | T1055 |
| Suspicious image load | `PsSetLoadImageNotifyRoutine` | Flags images mapped from `\temp\`, `\downloads\`, `\users\public\` or `\appdata\local\temp\` paths | - |
| Registry persistence | `CmRegisterCallbackEx` | Flags value writes under `...\CurrentVersion\Run` and `...\CurrentVersion\RunOnce` | T1547.001 |
| LSASS handle access | `ObRegisterCallbacks` (process handle create/duplicate) | Flags non-kernel handle requests to `lsass.exe` that include `PROCESS_VM_READ`, `PROCESS_VM_WRITE` or `PROCESS_VM_OPERATION`, and strips those access bits | T1003.001 |

Other details:

- Three severity levels (INFO, WARN, CRIT)
- 512-entry event ring buffer guarded by a spin lock; when full, new events are dropped and counted rather than blocking inside a callback
- Flat, pointer-free event structure copied to user mode with `METHOD_BUFFERED`
- Process/thread callbacks are required at load; image, registry and object callbacks are best-effort (failures are logged with `DbgPrint` and the driver keeps running)
- Callbacks are unregistered in reverse order on unload

## Architecture / How It Works

```
               kernel space                              user space
 +------------------------------------------+     +-----------------------------+
 | MyEdrDriver.sys                          |     | MyEdrClient.exe             |
 |                                          |     |                             |
 |  PsSetCreateProcessNotifyRoutineEx --+   |     |  CreateFile(\\.\MyEdr)      |
 |  PsSetCreateThreadNotifyRoutine -----+   |     |                             |
 |  PsSetLoadImageNotifyRoutine --------+   |     |  loop:                      |
 |  CmRegisterCallbackEx ---------------+   |     |    DeviceIoControl(         |
 |  ObRegisterCallbacks (LSASS) --------+   |     |      IOCTL_MYEDR_GET_EVENT) |
 |                                      |   |     |    print event, or          |
 |                                 push v   |     |    Sleep(50 ms) if empty    |
 |                  [ ring buffer, 512 ]    |     |              |              |
 |                                      |   |     |              |              |
 |  IRP_MJ_DEVICE_CONTROL <---- pop ----+ <-+-----+--------------+              |
 |                     (one event per call) |     |                             |
 +------------------------------------------+     +-----------------------------+
```

- The driver creates `\Device\MyEdr` with the symbolic link `\??\MyEdr`.
- `IOCTL_MYEDR_GET_EVENT` returns one `EDR_EVENT` per call, or `STATUS_NO_MORE_ENTRIES` when the queue is empty.
- `MyEdrDriver/src/Driver.h` is the shared contract (device names, IOCTL code, event struct) and is included by both the driver and the client.

## Tech Stack

- C
- Windows kernel-mode driver development (WDM)
- Windows Driver Kit (WDK)
- Visual Studio 2022, MSBuild, MSVC toolsets `WindowsKernelModeDriver10.0` and `v143`
- Win32 API (`CreateFileW`, `DeviceIoControl`)
- Kernel callbacks: `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallbackEx`, `ObRegisterCallbacks`
- IOCTL / IRP dispatch, spin locks, IRQL
- Target: Windows 10 x64
- Domain: EDR, endpoint security, threat detection, detection engineering, MITRE ATT&CK

## Getting Started

Windows only. These steps come from [TUTORIAL.md](TUTORIAL.md). They have not been verified by an automated build, and the [Known Issues](#known-issues) below may prevent the driver from building or loading as-is.

Requirements (inside a disposable VM):

- Windows 10 x64 (the tutorial uses 22H2)
- Visual Studio 2022 with the "Desktop development with C++" workload
- Windows Driver Kit (WDK) matching the installed Windows SDK, plus the WDK Visual Studio extension

1. Enable test signing in an elevated command prompt, then reboot:

   ```
   bcdedit /set testsigning on
   ```

2. Open `MyEDR.sln`, select **Debug | x64**, and build both projects. Output paths per the tutorial: `x64\Debug\MyEdrDriver\MyEdrDriver.sys` and `x64\Debug\MyEdrClient.exe`.

3. Load the driver from an elevated prompt in the folder containing the `.sys`:

   ```
   sc.exe create MyEdr type= kernel binPath= "%cd%\MyEdrDriver.sys"
   sc.exe start  MyEdr
   sc.exe query  MyEdr
   ```

   Driver `DbgPrint` output (`[MyEDR] ...`) can be viewed with Sysinternals DebugView with "Capture Kernel" enabled.

4. Run the client from a second elevated prompt:

   ```
   MyEdrClient.exe
   ```

   Output format:

   ```
   [INFO] proc-create   pid=<pid> creator=<pid> parent=<pid>  <image> :: Process created
   ```

5. Unload:

   ```
   sc.exe stop   MyEdr
   sc.exe delete MyEdr
   ```

The INF file is included because the WDK build expects one; the tutorial installs the driver with `sc.exe` instead.

## Project Structure

```
MyEDR/
├── MyEDR.sln
├── MyEdrDriver/
│   ├── MyEdrDriver.vcxproj    WDM driver project (x64 Debug/Release)
│   ├── MyEdrDriver.inf
│   └── src/
│       ├── Driver.h           shared contract: device names, IOCTL, EDR_EVENT
│       ├── Driver.c           DriverEntry, device + symlink, IOCTL dispatch, unload
│       ├── EventQueue.h       spinlock-guarded ring buffer
│       ├── Callbacks.c/.h     process and thread notify routines, PPID-spoof and remote-thread heuristics
│       ├── ImageLoad.c/.h     image-load callback, suspicious path heuristic
│       ├── Registry.c/.h      registry callback, Run/RunOnce persistence heuristic
│       └── ObjectGuard.c/.h   object callback, LSASS access detection and access stripping
├── MyEdrClient/
│   ├── MyEdrClient.vcxproj    Win32 console project
│   └── src/main.c             opens \\.\MyEdr, polls and prints events
└── TUTORIAL.md                build, load, test and extension guide
```

## Testing

There are no automated tests and no CI. Verification is manual, as described in [TUTORIAL.md](TUTORIAL.md): load the driver in a test VM, run the client, and trigger each behavior (for example, a benign `CreateRemoteThread` test program, or launching a process with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`).

## Known Issues

These were found by reading the source; they have not been confirmed on a running system.

- **`PsGetProcessImageFileName` is used but never declared.** It is an exported but undocumented routine that is not declared in `ntddk.h`. In C, the implicit declaration returns `int`, which truncates the 64-bit pointer on x64; dereferencing it can bugcheck the system. It needs an explicit prototype (`PCHAR PsGetProcessImageFileName(PEPROCESS);`). Used in `Callbacks.c` and `ObjectGuard.c`.
- **`/INTEGRITYCHECK` is not set.** `ObRegisterCallbacks` returns `STATUS_ACCESS_DENIED` unless the driver image is linked with `/INTEGRITYCHECK`, and `MyEdrDriver.vcxproj` does not set it. Microsoft's documentation states the same requirement for `PsSetCreateProcessNotifyRoutineEx`, which `DriverEntry` treats as mandatory, so the driver may fail to load until the linker flag is added.
- **Remote-thread detection is likely to false-positive on normal process launches.** When a process creates a child, the child's initial thread is created from the parent's context, so `PsGetCurrentProcessId() != ProcessId` and a CRIT `remote-thread` event is raised for ordinary process creation.
- **Registry callback constant.** `Registry.c` compares against `RegNmPreSetValueKey`; the WDK enum value is `RegNtPreSetValueKey`, so this may not compile as written.
- **No automated build, tests or CI.**

## Limitations / Roadmap

Current limitations:

- Heuristics are single signals with known benign cases (for example, legitimate parent-PID reassignment) and no scoring or correlation.
- The LSASS guard strips memory access from every non-kernel caller other than LSASS itself, including legitimate tools.
- Process names come from the 15-character short image name.
- The client polls every 50 ms instead of blocking; events are dropped when the 512-entry queue is full.
- Registry monitoring only covers value writes to Run/RunOnce keys.

Roadmap from the tutorial:

- Process tampering checks (hollowing / ghosting) by comparing the on-disk image with the mapped image
- Push-model delivery (inverted call / pended IRPs) instead of polling
- A richer UI and YARA scanning of suspicious buffers
