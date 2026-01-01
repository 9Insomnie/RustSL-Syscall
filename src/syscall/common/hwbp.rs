#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum HWBPType {
    Execute = 0b00,   // 只有执行时触发
    Write = 0b01,     // 写入时触发
    ReadWrite = 0b11, // 读取或写入时触发（某些架构不支持只读断点）
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum HWBPSize {
    Byte = 0b00,
    Word = 0b01,       // 2 字节
    DoubleWord = 0b11, // 4 字节
    QuadWord = 0b10,   // 8 字节
}

use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::GetCurrentThread;

const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;

pub unsafe fn set_hwbp(index: usize, address: usize, condition: HWBPType, size: HWBPSize) -> bool {
    let thread_handle = GetCurrentThread();

    // 现在 CONTEXT 应该能找到了
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // GetThreadContext 和 SetThreadContext 现在应该能链接到了
    if GetThreadContext(thread_handle, &mut ctx) == 0 {
        return false;
    }

    // ... 设置寄存器的逻辑不变 ...
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => return false,
    }

    // 设置 DR7 (启用 L0-L3 位，以及 RW/LEN 位)
    ctx.Dr7 &= !(0b11 << (index * 2));
    ctx.Dr7 |= 1 << (index * 2);
    let shift = 16 + (index * 4);
    ctx.Dr7 &= !(0b1111 << shift);
    let config = (condition as u64) | ((size as u64) << 2);
    ctx.Dr7 |= config << shift;

    SetThreadContext(thread_handle, &ctx) != 0
}

/// 清除硬件断点
pub unsafe fn clear_hwbp(index: usize) -> bool {
    if index > 3 {
        return false;
    }

    let thread_handle = GetCurrentThread();
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if GetThreadContext(thread_handle, &mut ctx) != 0 {
        ctx.Dr7 &= !(1 << (index * 2)); // 禁用对应的 L 位
        return SetThreadContext(thread_handle, &ctx) != 0;
    }
    false
}
