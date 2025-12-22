# RustSL Web GUI

使用 NiceGUI 构建的 RustSL Web 版本界面，一比一复刻PyQt5 GUI功能。

## 安装

```bash
# 安装依赖
pip install -r requirements.txt
```

## 运行

```bash
# 方式1：直接运行
python app.py

# 方式2：使用 NiceGUI CLI
nicegui run app.py
```

然后访问浏览器：`http://localhost:8050`

## 功能列表

✅ Shellcode 文件上传  
✅ Payload 加载方式选择  
✅ 加密方法选择  
✅ 编码方式选择  
✅ VM/沙箱检测选项  
✅ Syscall 方法选择  
✅ 内存分配模式  
✅ 运行模式配置  
✅ Icon 和文件捆绑  
✅ 目标架构选择  
✅ 签名配置  
✅ 实时日志输出  
✅ 进度条显示  
✅ Win7 兼容性和调试模式  

## 架构

- **前端**: HTML5 + Tailwind CSS（由 NiceGUI 自动生成）
- **后端**: Python FastAPI（由 NiceGUI 驱动）
- **配置**: 复用 `../config/plugins.json`
- **业务逻辑**: 可复用 `../gui/worker.py` 中的构建逻辑

## 对比

| 功能 | PyQt5 GUI | Web GUI |
|------|-----------|---------|
| 跨平台 | ✓ (需安装) | ✓ (浏览器) |
| 开发速度 | 中等 | 快速 |
| 学习曲线 | 陡峭 | 平缓 |
| 部署复杂度 | 中等 | 简单 |
| 网络共享 | ✗ | ✓ |
| 外观定制 | 中等 | 灵活 |

## 配置修改

所有配置项（加密方法、运行模式等）都从 `config/plugins.json` 动态加载，修改该文件即可自动更新Web界面。

## 集成后端构建逻辑

当前 Web 应用已预留接口用于集成实际的构建逻辑：

```python
# 在 run_all() 中替换模拟构建
worker = WorkerThread(self, params)  # 使用真实 worker
worker.log_signal.connect(self.log_append)
worker.progress_signal.connect(lambda p: setattr(self.progress_bar, 'value', p/100))
worker.start()
```

## TODO

- [ ] 集成真实的 WorkerThread 构建逻辑
- [ ] 添加文件上传进度显示
- [ ] 实现实时日志流式输出
- [ ] 添加导出日志功能
- [ ] 支持多语言界面
- [ ] 添加配置预设保存/加载
