# RustSL —— syscall

### 项目概述
RSL-SYSCALL 是 [RustSL](https://github.com/echQoQ/RustSL)的 syscall 版本，专注于使用多种先进的 syscall invocation 技术来实现高效的 shellcode 加载和执行，同时绕过常见的安全检测机制。该项目结合 syscall 绕过技术，适用于渗透测试等场景。

---

**免责声明**：本项目尚不成熟，也不保证稳定性以及免杀性，仅供教育和研究目的使用。并且使用者应确保其行为符合当地法律法规。作者不对任何非法使用或由此产生的后果承担责任。请在受控环境中测试和使用。

---

### 使用方法

环境配置参见[RustSL 文档](https://github.com/echQoQ/RustSL)
与之类似，除GUI外，新增了 web 界面
配置完环境后，运行以下命令启动对应界面：
- web:
```
python web.py
```

- gui:
```
python gui.py
```

### 核心技术与功能
- **Syscall Invocation 技术**：项目实现了多种 syscall 调用方法，包括：
  - SysWhispers
  - Hell's Gate
  - Tartarus' Gate
  - HWBP（Hardware Breakpoint）
  - KFD Syscall
- **Threadless Injection 技术**：用于无线程 shellcode 注入和执行，包括：
  - Early Cascade
  - Early Exception Inject
  - Entry Point Injection
  - Hook Bypass Injection
  - Pool Party
- **Shellcode 执行**：支持多种解密和执行方式，包括 AES、ECC、RC4、XChaCha20 等加密算法，以及 IPv4/IPv6、MAC、UUID 等数据处理。
- **模块化设计**：项目分为多个模块，如 syscall（syscall 调用）、exec（执行逻辑）、decrypt（解密）、load（加载）、sandbox（沙箱检测）等，便于扩展和维护。

### 使用场景与注意事项
- **适用场景**：渗透测试、红队演练、绕过 EDR（Endpoint Detection and Response）等安全工具。
- **注意事项**：项目涉及 syscall 级别的底层操作，可能触发安全检测；建议在受控环境中测试。

## 致谢

特别感谢以下开源项目和技术贡献者：

- [SysWhispers](https://github.com/jthuraisamy/SysWhispers)
- [Hell's Gate](https://github.com/am0nsec/HellsGate)
- [Tartarus' Gate](https://github.com/trickster0/TartarusGate)
- [EarlyExceptionHandling](https://github.com/kr0tt/EarlyExceptionHandling)
- [HWSyscalls](https://github.com/Dec0ne/HWSyscalls)
- [rust-mordor-rs](https://github.com/gmh5225/rust-mordor-rs)
- [earlycascade-injection](https://github.com/Whitecat18/earlycascade-injection)
- [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk)
- [Unwinder](https://github.com/Kudaes/Unwinder)
- [PoolParty](https://github.com/SafeBreach-Labs/PoolParty)
- 等等

### 许可证

本项目采用 MIT 许可证，详情请参阅 LICENSE 文件。