# 工具脚本说明

## 交付门禁（推荐）

一条命令串行执行 route4 回归和 demo 冒烟：

```powershell
python tools/run_delivery_check.py --project-root Z:\2026\0217_vmp_project\VmpProject
```

默认执行顺序：

1. `tools/run_regression.py --patch-vmengine-symbols`
2. `tools/run_demo_vmp_verify.py`

最终会输出 `DELIVERY_GATE PASS` 或 `DELIVERY_GATE FAIL`。

## 回归脚本

`run_regression.py` 覆盖端到端启动回归：

1. 构建并执行 `VmProtect` 导出产物
   - 自动探测 `cmake` / `ninja` / `gcc` / `g++`
   - 配置并构建 `VmProtect`
   - 运行 `VmProtect.exe` 导出 `fun_*.txt/bin`、`libdemo_expand.so` 等产物
   - 校验并复制导出文件到 `VmEngine/app/src/main/assets`
   - 当启用 `--patch-vmengine-symbols` 时，使用 `VmProtect` 主流程参数
     `--vmengine-so/--output-so` 生成 `libvmengine_patch.so`
2. 执行 `VmEngine/gradlew.bat installDebug`
3. 执行 `adb shell am start -W -n com.example.vmengine/.MainActivity`
4. 采集 `logcat` 并做关键字判定

基础用法：

```powershell
python tools/run_regression.py --project-root Z:\2026\0217_vmp_project\VmpProject
```

可选参数示例：

```powershell
python tools/run_regression.py --package com.example.vmengine --activity .MainActivity
python tools/run_regression.py --functions fun_add fun_for
```

## Route4 L1 Embed 脚本

将 `libdemo_expand.so` 以尾部附加方式写入 `libvmengine.so`：

```powershell
python tools/embed_expand_into_vmengine.py `
  --host-so <path-to-libvmengine.so> `
  --payload-so Z:\2026\0217_vmp_project\VmpProject\VmEngine\app\src\main\assets\libdemo_expand.so
```

可选输出路径：

```powershell
python tools/embed_expand_into_vmengine.py `
  --host-so <path-to-libvmengine.so> `
  --payload-so <path-to-libdemo_expand.so> `
  --output-so <path-to-patched-libvmengine.so>
```

## Route4 L2.5 Stub 生成器

根据 manifest 生成 arm64 symbol stub（`.S`）和 symbol-id 头文件：

```powershell
python tools/gen_takeover_stubs.py `
  --manifest tools/takeover_symbols.json `
  --manifest-label tools/takeover_symbols.json `
  --out-asm VmEngine/app/src/main/cpp/generated/zTakeoverStubs.generated.S `
  --out-header VmEngine/app/src/main/cpp/generated/zTakeoverSymbols.generated.h
```

manifest 示例（`tools/takeover_symbols.json`）：

```json
{
  "symbols": [
    { "id": 0, "name": "fun_add" },
    { "id": 1, "name": "fun_for" },
    { "id": 2, "name": "fun_if_sub" }
  ]
}
```

`VmEngine/app/src/main/cpp/CMakeLists.txt` 会在 configure 阶段自动执行该生成脚本。

## 说明

- 运行环境需要可用 `python`（在 PATH 中）。
- 脚本会从 `VmEngine/local.properties`（`sdk.dir`）自动探测 `adb`。
- `VmEngine` Debug native 构建默认启用 route4 embed（`VMENGINE_ROUTE4_EMBED_PAYLOAD=ON`）。
- 回归关键 marker：
  - `route_embedded_expand_so result=1 state=0`
  - `route_symbol_takeover result=1`
- `route_embedded_expand_so` 判定策略：
  - `state=0` 表示通过（embedded payload 已执行）
  - `result=0` 表示失败
