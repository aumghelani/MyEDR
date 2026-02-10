# Building MyEDR — a minimal Windows EDR, from scratch

This is a learning project. You build a small **Endpoint Detection and Response**
tool for Windows: a kernel driver that watches the system using documented
notification callbacks, and a user-mode console that displays what it sees.

It is deliberately small so you can understand every line. Once it works you
extend it. The reference project `BestEdrOfTheMarket` shows where this can go.

> **Safety first.** Kernel bugs crash the whole machine (BSOD). Do all of this
> inside a **disposable Windows VM** with snapshots, never on a machine you care
> about. This tool is defensive and for your own test box only.

---

## 0. What you are building

```
            kernel space                         user space
  ┌───────────────────────────────┐     ┌──────────────────────────┐
  │  MyEdrDriver.sys               │     │  MyEdrClient.exe         │
  │                                │     │                          │
  │  PsSetCreateProcessNotifyEx ─┐ │     │  CreateFile(\\.\MyEdr)   │
  │  PsSetCreateThreadNotify ────┤ │     │                          │
  │                             push     │  loop:                   │
  │                    [ event queue ]   │    DeviceIoControl(      │
  │                              │       │       IOCTL_GET_EVENT) ──┼─ reads
  │  IRP_MJ_DEVICE_CONTROL ◄─────┘◄──────┼── one event per call     │
  └───────────────────────────────┘     └──────────────────────────┘
```

- The driver **subscribes** to process- and thread-creation events.
- It turns each interesting observation into a flat `EDR_EVENT` record.
- It **enqueues** records in a spinlock-guarded circular buffer.
- The client **polls** one IOCTL and prints each event.

Two detections are built in to start:
1. **PPID spoofing** (MITRE T1134.004): a process claims a parent different
   from the process whose thread actually created it.
2. **Remote thread creation** (T1055): a thread is created into a process by a
   *different* process — the classic injection primitive.

---

## 1. Set up the toolchain (inside the VM)

1. Install **Windows 10 22H2 x64** in a VM (VMware Fusion / Parallels / UTM / Hyper-V).
   Take a snapshot named `clean`.
2. Install **Visual Studio 2022** with the *Desktop development with C++* workload.
3. Install the **Windows Driver Kit (WDK)** that matches your Windows SDK
   version, plus the *WDK Visual Studio extension*. See Microsoft's
   "Download the WDK" page.
4. Enable test signing so Windows will load an unsigned driver. In an
   **admin** command prompt:
   ```
   bcdedit /set testsigning on
   ```
   Reboot. You should see "Test Mode" watermarked in the desktop corner.

---

## 2. Build

Open `MyEDR.sln` in Visual Studio. Set the configuration to **Debug / x64**.

- Build **MyEdrDriver** → produces `x64\Debug\MyEdrDriver\MyEdrDriver.sys`.
- Build **MyEdrClient** → produces `x64\Debug\MyEdrClient.exe`.

(If the driver project shows an "inf2cat" or signing error, it is only the
test-cert/catalog step; for loading with test signing you can ignore catalog
generation. The `.sys` still builds.)

---

## 3. Load the driver

Copy `MyEdrDriver.sys` into the VM if you built on another machine. In an
**admin** command prompt in the folder with the `.sys`:

```
sc.exe create MyEdr type= kernel binPath= "%cd%\MyEdrDriver.sys"
sc.exe start  MyEdr
```

Check it is running:
```
sc.exe query MyEdr
```
`STATE : 4 RUNNING` means the driver loaded and `DriverEntry` succeeded.

To watch its `DbgPrint` output, run **DebugView** (Sysinternals) as admin with
*Capture Kernel* enabled. You should see `[MyEDR] loaded` and
`[MyEDR] callbacks registered`.

---

## 4. Run the client and generate events

In a second **admin** prompt:
```
MyEdrClient.exe
```
You will see a line for every process that starts or exits, e.g.:
```
[INFO] proc-create   pid=4812 creator=9001 parent=9001  notepad.exe :: Process created
[INFO] proc-exit     pid=4812 creator=0    parent=0     notepad.exe :: Process exited
```

Now trigger the detections:
- **Remote thread**: run any tool that does `CreateRemoteThread` into another
  process (a benign test injector you write, or a DLL-injection sample you
  control). You should get a `CRIT remote-thread` line naming injector and victim.
- **PPID spoofing**: launch a process with a forged parent
  (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`). You should get a `WARN proc-create`
  line saying the claimed parent differs from the real creator.

---

## 5. Unload / reset

```
sc.exe stop   MyEdr
sc.exe delete MyEdr
```
If anything misbehaves, revert the VM to the `clean` snapshot.

---

## 6. How the code is organized

| File | Role |
|------|------|
| `MyEdrDriver/src/Driver.h` | Shared contract: device name, IOCTL, `EDR_EVENT`. Included by both sides. |
| `MyEdrDriver/src/EventQueue.h` | Spinlock-guarded circular queue of events. |
| `MyEdrDriver/src/Callbacks.c` | The notify routines + detection heuristics. **The brain.** |
| `MyEdrDriver/src/Driver.c` | `DriverEntry`, device + symlink, IOCTL dispatch, unload. |
| `MyEdrClient/src/main.c` | Opens the device, polls events, prints them. |

Read them in that order. Every function has comments explaining the *why*.

---

## 7. Key concepts to internalize

- **Notification callbacks vs hooking.** We never patch the kernel. We register
  with documented APIs (`PsSetCreateProcessNotifyRoutineEx`,
  `PsSetCreateThreadNotifyRoutine`) that the kernel *invites* us into. Stable,
  supported, and what real EDRs lean on heavily.
- **IRQL and spin locks.** Callbacks can run at raised IRQL and concurrently on
  many cores. Shared state (the queue) must be protected by a spin lock, and we
  must never do pageable or blocking work while holding one.
- **The kernel/user boundary.** User-mode cannot read kernel memory directly.
  We define a flat struct with no pointers and copy it through the IOCTL's
  system buffer (`METHOD_BUFFERED`).
- **Heuristics are signals, not proof.** "Parent pid != creator pid" is a
  strong hint of spoofing but has benign cases. Real EDRs score and correlate
  many signals. Start simple, measure false positives, then refine.

---

## 8. Extend it (your roadmap)

Already implemented in this repo:

1. **Image load callback** (`PsSetLoadImageNotifyRoutine`) — `ImageLoad.c`.
   Flags images mapped from temp/downloads/public paths.
2. **Registry callback** (`CmRegisterCallbackEx`) — `Registry.c`. Flags writes
   to Run / RunOnce autostart keys (T1547.001).
3. **Object callbacks** (`ObRegisterCallbacks`) — `ObjectGuard.c`. Detects
   handle opens to LSASS with memory-read access (credential dumping,
   T1003.001) and strips the dangerous access bits.

Still on the roadmap:

4. **Process tampering checks**: detect hollowing/ghosting by comparing the
   on-disk image to the mapped image (the reference uses the VAD tree).
5. **Push instead of poll**: use an inverted-call / pended-IRP model so the
   client blocks until an event is ready, instead of polling.
6. **A real UI** and YARA scanning of suspicious buffers.

> Note on the object callback: `ObRegisterCallbacks` requires the driver image
> to be signed, or loaded under test signing. Under `testsigning` mode (step 1)
> it registers fine. On a production machine it needs an EV cert and the
> `/integritycheck` linker flag.

Each of these is one new callback plus one new `EDR_EVENT` type. The skeleton
here is built to grow that way.

---

## 9. Reference

- MITRE ATT&CK technique pages linked above.
- Microsoft "Windows Driver Kit" and "Process and thread notify routines" docs.
- The `BestEdrOfTheMarket` project for a fuller, v3-grade implementation to read.
