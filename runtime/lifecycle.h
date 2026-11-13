// Lifecycle orchestration, PASSIVE_LEVEL only.
// Startup builds private subsystems before BFE subscription and publishes
// the device last. Shutdown closes control/telemetry/injection producers,
// unsubscribes and drains BFE callbacks, closes the dynamic WFP session,
// drains flow contexts, then unregisters runtime callouts. Only confirmed
// quiescence permits pool, rule snapshot, and device destruction.
// Failed startup follows the same ownership rules; rollback never discards
// an unconfirmed registration or returns an unloadable failure state.
#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// 启动全部子系统(设备(DriverEntry 创建, SK_STEP_DEVICE 跟踪) → rules →
// telemetry → control(仅线程/请求门就绪, 不代表设备已建) → inject → BFE → wfp)。
// 任一步失败内部回滚(同一 quiesce/destroy 对, 含设备步); 回滚失败 => 驻留。
NTSTATUS SkLifecycleStart(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT wdmDevice);
// quiesce 全部子系统; FALSE = 未达 quiescent(原因已由子系统记录)
BOOLEAN SkLifecycleQuiesce(void);
// destroy 阶段(仅 runtime 门禁放行时执行)。规则快照 shutdown drain 失败
// => UNLOAD_BLOCKED 终态且 destroy 链立即停止(后续 destroy 不执行,
// 步骤标志保留); 状态经 runtime 状态机传播, ShRuntimeRunUnload 复核驻留。
VOID SkLifecycleDestroy(void);

#ifdef __cplusplus
}
#endif
