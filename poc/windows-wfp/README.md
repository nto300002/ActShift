# Windows WFP PoC (stage 1: native application identity)

This is a small, standalone **test program**, not the ActShift application. When
double-clicked it shows a text menu and stays open until you choose Exit. It
does not run in the background; closing the window does not remove any
previously installed persistent filter. It installs
two persistent Windows Filtering Platform (WFP) filters at
`FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`. Both match the
WFP application ID derived from one executable path and block its outbound
connections. The executable may still launch. Other applications do not match
these filters. The PoC owns its provider, sublayer, and filter GUIDs and removes
only those objects.

**This does not identify a website.** At ALE, an application ID identifies the
browser executable, not the requested hostname. Blocking Chrome here would block
all of Chrome's traffic. Do not use this program to claim that Issue #2's
site-specific, shared-CDN, DNS, VPN, first-access, or selective-failure criteria
have passed. See [the coverage table](#issue-2-coverage).

## Build on Windows 11

Install Visual Studio 2022 Build Tools or Visual Studio with **Desktop development
with C++**, the Windows 11 SDK, and CMake. From a Developer PowerShell:

```powershell
cmake -S poc/windows-wfp -B poc/windows-wfp/build -A x64
cmake --build poc/windows-wfp/build --config Release
```

Run the resulting `poc\windows-wfp\build\Release\actshift-wfp-poc.exe`. For an
ARM64 native binary, use `-A ARM64` with the matching MSVC/SDK components. The
included CI build checks x64. The program uses only user-mode WFP management
APIs; no kernel driver or browser extension is installed.

The GitHub Actions x64 artifact is **unsigned**. A SmartScreen "unknown
publisher" warning is expected for a new unsigned build and does not prove
either that the file is safe or that it is malicious. Download only from this
repository's successful Actions run, compare the executable's SHA-256 with the
hash shown in that run's summary, and review the source before running it.
Do not turn off SmartScreen for this test. If your PC's policy will not allow
an unsigned executable, build and run the source in a controlled test
environment instead. Code signing for wider distribution remains open.

## Safe first run

Use a test Windows account or test PC and an **elevated** PowerShell for policy
changes. Keep a second elevated terminal and a copy of this executable available
for recovery. Do not choose your browser, shell, VPN, security tool, or the PoC
executable as the target in the first run. A low-impact target is Windows' own
`curl.exe`; confirm that it exists before starting.

```powershell
$poc = ".\poc\windows-wfp\build\Release\actshift-wfp-poc.exe"
$target = "$env:WINDIR\System32\curl.exe"
& $target -I --max-time 10 https://example.com
& $poc status
& $poc block-app $target
& $poc status
& $target -I --max-time 10 https://example.com
```

The first `curl` request should succeed and the last should fail. Confirm in
Edge that `https://example.com` still opens. Repeat with `curl.exe -4` and `-6`
only when both IP families work in the baseline network; record unsupported
network paths as untested. For a non-browser native application test, replace
`curl.exe` with the full path to a disposable test application, then confirm it
still launches while its network request fails.

Remove the policy before ending the test:

```powershell
& $poc remove
& $poc status
& $target -I --max-time 10 https://example.com
```

`remove` is idempotent and works offline. It deletes the two filters, their
sublayer, and their provider in one WFP transaction. It does not stop the Base
Filtering Engine or alter any other provider. The filters are **persistent**:
closing this CLI does not remove them, and they are expected to return after a
reboot. Always test and document `remove` before rebooting with a filter active.
If the CLI is unavailable, this stage has **no independently verified OS-only
recovery path** yet; do not run fault-injection tests on an irreplaceable PC.

If `block-app` reports an existing object, run `remove` and retry. Installing a
new target does not silently overwrite the prior target. File identity may
change when the executable is updated or moved; this must be tested separately.

## Evidence to collect

For each run, record Windows edition/build/architecture, build architecture,
test executable path and version, whether the terminal was elevated, NIC mode,
IPv4/IPv6 availability, timestamp, command, exit code, expected result, actual
result, and a screenshot or log. Do not publish personal device IDs or raw
network addresses. Record the last successful request before adding the filter,
the first failure after adding it, and the first success after `remove`.

For a WFP inventory, an administrator can run `netsh wfp show state` and inspect
the generated `wfpstate.xml` for the `ActShift WFP PoC` provider and its objects.
`netsh wfp show state` is observational; it is not the recovery command.

## Issue #2 coverage

| Issue #2 area | What this stage can measure | What remains open |
| --- | --- | --- |
| Native app | Outbound block by executable identity; app still launches; unrelated app works | Updates/relocation, packaged apps, all traffic paths |
| IPv4/IPv6 | Separate ALE AUTH_CONNECT filters for both families | Actual IPv6 availability and all transport/VPN combinations |
| Persistence | Filter presence after CLI exit and reboot | BFE startup gap and boot-time filtering |
| Recovery | Offline elevated `remove` for PoC-owned objects | Separate recovery tool and independently verified OS management fallback |
| Browsers/sites | No site-level claim | Hostname classification in Chrome, Firefox, Edge; shared CDN, encrypted DNS, QUIC, VPN |
| Timer/first access | No timer or first-access claim | IDLE/ALLOW/BLOCK state machine and first packet detection |
| Existing flows | Can measure before/after requests | Confirmed termination latency of established TCP/QUIC flows |
| Failure isolation | CLI exit leaves persistent filters | Service/component crash and selective unknown-traffic handling |

The current code is deliberately a **partial result** for [Issue #2](https://github.com/nto300002/ActShift/issues/2).
Any untested or failed row must remain open there. In particular, WFP application
identity plus an IP address is not a website identity.

## API references

- [ALE and application identity](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
- [WFP object lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
- [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)
- [WFP filter structure](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
