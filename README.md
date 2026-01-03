# RustSL —— syscall

### 项目概述
RusSL-SYSCALL 是 [RustSL](https://github.com/echQoQ/RustSL)的 syscall 版本，专注于使用间接系统调用、无线程注入、PPID伪造等多种先进的免杀技术相互结合，从而实现隐蔽的 shellcode 加载和执行。

---

### **免责声明**：

- 本项目尚不成熟，也不保证兼容性、稳定性以及免杀性，仅供教育和研究目的使用，所以请尽量不要以被XXX检测到为由提交ISSUE。项目兼容性也有限，如有问题请自行排查。
- 使用者应确保其行为符合当地法律法规,作者不对任何非法使用或由此产生的后果承担责任。
- 请在受控环境中测试和使用。

---

### 使用方法

Rust环境配置参见[原RustSL 文档](https://github.com/echQoQ/RustSL)
本项目与原项目类似，但除GUI外，新增了 web 界面
配置完环境后，运行以下命令启动对应界面：
- web:
```
pip install -r web/requirements.txt
python web.py
```
![alt text](static/web.png)


- gui:
```
pip install -r gui/requirements.txt
python gui.py
```

![alt text](static/gui.png)

---

### 核心技术与功能

#### 1. Syscall 技术概览
本项目实现了多种动态获取系统调用号（SSN）及执行系统调用的方案，旨在规避用户态 Hook。

| 技术名称 | 实现原理 |
| :--- | :--- |
| **FreshyCalls / SysWhispers** | 遍历 `ntdll.dll` 导出表中所有以 `Zw` 开头的函数地址并进行升序排序。由于系统调用号在内核中是连续分配的，函数在排序后的列表中的索引即为其对应的 SSN。这种方法不依赖于函数体内的指令特征，具有极高的版本兼容性。 |
| **HellsHalos + TartarusGate** | 动态解析内存中 `ntdll.dll` 的导出表，搜索 `mov eax, SSN` 指令获取系统调用号。当目标函数被 Hook（如首字节为 `0xE9`）时，Halo's Gate 会通过向上或向下搜索相邻函数的指令特征来推算正确的 SSN。Tartarus' Gate 则进一步深入搜索函数体内的指令序列，通过更复杂的模式匹配来识别被修改后的函数中的原始 SSN。 |
| **Hardware Syscalls** | 利用 CPU 调试寄存器（Dr0-Dr3）在目标 API 入口点设置硬件执行断点。当程序尝试调用该 API 时触发单步异常，由注册的向量化异常处理程序（VEH）捕获。在异常上下文中手动修改 `Rax` 为 SSN，并将 `Rip` 重定向到 `ntdll` 内部的 `syscall` 指令，实现无代码修改的系统调用劫持。 |
| **KFD (Konflict)** | 结合了动态 SSN 获取与间接调用技术。首先解析目标函数的 SSN，然后在 `ntdll.dll` 中寻找合法的 `syscall; ret` 指令片段（Gadget）。最后在内存中动态创建一个微型存根（Stub），该存根负责设置寄存器并跳转到 `ntdll` 内部执行，从而实现隐蔽的间接系统调用。 |
| **Stack Spoofing** | 在发起系统调用前，通过搜索堆栈找到如 `BaseThreadInitThunk` 等合法函数的返回地址。利用精心构造的汇编 Gadget（如 `jmp rbx`）修改返回路径，确保 EDR 在任何时刻观察到的调用栈都完全由合法的系统模块组成。 |

#### 2. Exec 注入与执行策略
提供多样化的 Shellcode 执行手段，支持通过 Cargo Features 灵活组合。

| 技术名称 | 实现原理 |
| :--- | :--- |
| **NtCreateThreadEx / APC** | 使用 `NtCreateThreadEx` 在目标进程中创建新线程执行 Shellcode，或利用 `NtQueueApcThread` 将 Shellcode 作为异步过程调用（APC）插入目标线程队列，等待线程进入可警告状态（Alertable）时触发执行。 |
| **HWBP Bypass** | 在调用如 `NtAllocateVirtualMemory` 等敏感 API 前，临时开启硬件断点监控。通过 VEH 捕获调用意图，并手动模拟系统调用过程，从而跳过 EDR 在 API 入口处设置的内联钩子（Inline Hooks）。 |
| **Early Cascade Injection** | 创建挂起状态的目标进程，通过修改其 `.data` 段中的 `g_ShimsEnabled` 标志和劫持 `g_pfnSE_DllLoaded` 函数指针。当进程恢复运行时，在 DLL 加载的极早期阶段触发回调执行 Shellcode。 |
| **Early Exception Injection** | 在新进程启动初期，通过硬件断点劫持 `KiUserExceptionDispatcher`。利用进程初始化时的异常分发机制，将执行流重定向到 Shellcode，从而在 EDR 监控逻辑完全加载前完成注入。 |
| **Process Hollowing** | 以挂起模式启动一个合法的系统进程（如 `svchost.exe`），使用 `NtUnmapViewOfSection` 卸载其原始镜像内存，随后在相同基址处映射恶意载荷镜像，并修改线程上下文的 `Rcx` (入口点) 后恢复运行。支持 **PPID 伪造**，使新进程看起来是由指定的合法父进程（如 `explorer.exe`）创建的。 |
| **PPID Spoofing** | 在创建新进程时，通过修改进程创建属性列表（Attribute List），将父进程 ID 指向一个已存在的合法进程（如 `lsass.exe` 或 `explorer.exe`）。这能有效规避 EDR 对异常进程树（Process Tree）的监控。该技术被广泛应用于 **Process Hollowing**、**Early Cascade**、**Early Exception** 以及 **Entry Point Injection** 等注入模块中。 |

---

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
- 等等

### 许可证

本项目采用 MIT 许可证，详情请参阅 LICENSE 文件。