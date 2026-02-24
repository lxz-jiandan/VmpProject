# Regression Script

`run_regression.py` runs end-to-end startup regression:

1. Build and export artifacts from `VmProtect`:
   - detect `cmake` / `ninja` / (`gcc` + `g++`)
   - configure + build `VmProtect`
   - run `VmProtect.exe` to export artifacts
   - verify and copy exported assets to `VmEngine/app/src/main/assets`
2. `VmEngine/gradlew.bat installDebug`
3. `adb shell am start -W -n com.example.vmengine/.MainActivity`
4. `logcat` keyword checks

## Usage

```powershell
python tools/run_regression.py --project-root Z:\2026\0217_vmp_project\VmpProject
```

Optional:

```powershell
python tools/run_regression.py --package com.example.vmengine --activity .MainActivity
python tools/run_regression.py --functions fun_add fun_for
```

## Route4 L1 Embed Script

Patch `libvmengine.so` by appending `libdemo_expand.so` payload at file tail:

```powershell
python tools/embed_expand_into_vmengine.py `
  --host-so <path-to-libvmengine.so> `
  --payload-so Z:\2026\0217_vmp_project\VmpProject\VmEngine\app\src\main\assets\libdemo_expand.so
```

Optional output path:

```powershell
python tools/embed_expand_into_vmengine.py `
  --host-so <path-to-libvmengine.so> `
  --payload-so <path-to-libdemo_expand.so> `
  --output-so <path-to-patched-libvmengine.so>
```

## Route4 L2.5 Stub Generator

Generate arm64 symbol stubs (`.S`) and symbol-id header from a manifest:

```powershell
python tools/gen_takeover_stubs.py `
  --manifest tools/takeover_symbols.json `
  --manifest-label tools/takeover_symbols.json `
  --out-asm VmEngine/app/src/main/cpp/generated/zTakeoverStubs.generated.S `
  --out-header VmEngine/app/src/main/cpp/generated/zTakeoverSymbols.generated.h
```

Manifest example (`tools/takeover_symbols.json`):

```json
{
  "symbols": [
    { "id": 0, "name": "fun_add" },
    { "id": 1, "name": "fun_for" },
    { "id": 2, "name": "fun_if_sub" }
  ]
}
```

`VmEngine/app/src/main/cpp/CMakeLists.txt` now auto-runs this generator at configure time.

## Notes

- The host must provide a Python interpreter (`python` in PATH).
- The script auto-detects `adb` from `VmEngine/local.properties` (`sdk.dir`).
- `VmEngine` Debug native build now auto-runs route4 embedding (`VMENGINE_ROUTE4_EMBED_PAYLOAD=ON` by default).
- The script checks these route4-only markers:
  - `route_embedded_expand_so result=1 state=0`
  - `route_symbol_takeover result=1`
- `route_embedded_expand_so` state policy:
  - `state=0` pass (embedded payload executed)
  - `result=0` fail
