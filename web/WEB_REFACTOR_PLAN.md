# RustSL Web（NiceGUI）重构方案

## 目标
- 复刻原 PyQt5 GUI 的布局与核心功能：参数配置、加密、构建、复制输出、可选签名。
- 支持现有 `config/plugins.json` 配置（encryption/encodings/vm_checks/run_modes/alloc_mem_modes/load_payload_modes/syscall_methods/defaults）。
- 运行环境：conda py312，已安装 nicegui；在仓库根目录运行。

## 模块划分
- `web/config_loader.py`
  - `ROOT`：仓库根路径。
  - `load_plugins_manifest()`：读取配置。
  - `_safe_default_id()`：默认值安全回退。
  - `get_defaults()` / `get_encodings()` / `build_feature_maps()`：解析 defaults 与 feature 映射。
- `web/pipeline.py`
  - `run_subprocess()`：异步子进程执行与日志收集。
  - `build_features()`：根据参数与映射生成 feature 列表。
  - `encrypt_payload()`：调用 `encrypt.py` 生成 `output/encrypt.bin`。
  - `build_rust()`：设置 env（run_mode pattern、icon、cmdline payload、bundle 等），执行 `cargo build --release --no-default-features --features=... --target=...`。
  - `copy_output()`：复制 `target/<triple>/release/rsl.exe` 到 `output/<rand>.exe`。
  - `sign_executable()`：调用 `sign/sigthief.py` 可选签名。
- `web/ui_components.py`
  - `RustSLWebGUI`：完整 UI + 事件 + 参数收集 + 调用 pipeline。界面分区：Shellcode/Load、加密/编码、VM 检测、Syscall、内存模式、Run 模式（pattern 1/2/3 显隐）、Icon/捆绑、Target/签名、日志+进度+开关（Win7/Debug）。
- `web/app.py`
  - 入口与路由：`@ui.page('/')` 创建页面，运行 `ui.run(...)`。

## 运行方式
```bash
conda activate py312
python web/app.py
```

## 流程逻辑
1) UI 收集参数，安全默认值回退避免 options 缺失报错。
2) `encrypt_payload`：生成 `output/encrypt.bin`。
3) `build_rust`：按参数拼 features，写入 env（RSL_TARGET_PROGRAM / RSL_TARGET_PID / RSL_DEFAULT_PAYLOAD_ADDRESS / RSL_BUNDLE_FILE / RSL_BUNDLE_FILENAME / RSL_ICON_PATH），cargo 构建。
4) `copy_output`：将构建产物复制到 `output/<rand>.exe`。
5) 可选 `sign_executable`：用签名源文件覆盖输出。
6) 进度：加密(0→40) / 构建(40→60) / 复制(→90) / 签名(→95) / 完成(100)。

## 验证建议
- 默认路径（无上传）流程：encrypt→cargo→copy 成功，日志与进度正常。
- run_mode pattern 2/3：目标路径与 PID 显隐，env 注入正确。
- load_payload_mode=cmdline：默认地址写入 env。
- forgery 启用时必须选择 bundle；未选时报错提示。
- 签名启用需签名源文件；未选时报错提示。
- Win7/Debug 选项生成 feature 位。

## 后续可选优化
- 在 UI 上提示当前 defaults 回退值。
- 追加错误提示的友好文案与快速清理按钮。
- 如需包形式运行，可改为 `python -m web.app` 并添加 `__init__.py`（当前已通过 sys.path 注入支持 `python web/app.py`）。
