# MyEDR

A minimal, educational Windows **Endpoint Detection and Response** lab: a WDM
kernel driver that observes process/thread activity via documented
notification callbacks, plus a user-mode console that displays the telemetry.

Built to learn Windows kernel internals and detection engineering from the
ground up. For use only in a disposable test VM.

## Layout

- `MyEdrDriver/` — the kernel driver (`MyEdrDriver.sys`)
- `MyEdrClient/` — the user-mode console (`MyEdrClient.exe`)
- `TUTORIAL.md` — step-by-step build, load, test and extension guide

## Detections (initial)

- **PPID spoofing** — claimed parent differs from the real creating process (T1134.004)
- **Remote thread creation** — a thread injected into another process (T1055)

## Quick start

See [`TUTORIAL.md`](TUTORIAL.md). In short: build in VS2022 + WDK, enable
`testsigning`, `sc create/start MyEdr`, then run `MyEdrClient.exe`.

## Status

Early skeleton. Roadmap (image-load, registry, object callbacks, tamper checks,
push-model delivery) is in the tutorial.
