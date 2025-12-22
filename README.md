# RustSL —— syscall

RustSL的 Syscall 版本，采用了多种先进的syscall invocation技术，包括SysWhispers生成的动态syscall stubs、Hell's Gate的直接syscall调用、Tartarus' Gate的gate机制、硬件断点辅助的syscall执行，以及threadless injection技术，以实现高效的shellcode加载和执行，同时绕过常见的安全检测。

## 致谢

特别感谢以下开源项目和技术贡献者：

- [SysWhispers](https://github.com/jthuraisamy/SysWhispers)
- [Hell's Gate](https://github.com/am0nsec/HellsGate)
- [Tartarus' Gate](https://github.com/trickster0/TartarusGate)
- [EarlyExceptionHandling](https://github.com/kr0tt/EarlyExceptionHandling)
- [HWSyscalls](https://github.com/Dec0ne/HWSyscalls)
- [rust-mordor-rs](https://github.com/gmh5225/rust-mordor-rs)
- [earlycascade-injection](https://github.com/Whitecat18/earlycascade-injection)
- 其他相关syscall技术和工具的贡献者