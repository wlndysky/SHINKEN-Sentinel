// ============================================================================
// runtime/lifecycle.h — 子系统生命周期编排(严格顺序, 见 docs/UNLOAD_SAFETY.md §7)
//
// quiesce 顺序(失败即 FALSE, 由 runtime 驻留):
//   1. 关闭 IOCTL 新请求门(control/ioctl.c)
//   2. 关闭规则写入门(rules/rule_store.c)
//   3. 关闭遥测生产者门(telemetry/event_queue.c)
//   4. 关闭注入门(packet/injection.c, ShInjectionGateStop)
//   5. 退订 BFE + drain BFE 回调 rundown
//   6. 注销全部 callout(WFP 文档化安全点; BUSY 重试间摘 flow context)
//   7. drain classify/注入/work item rundown
//   8. 停/join 事件线程
// destroy 顺序(quiescent 后): 删 filter/callout/sublayer/provider →
//   销毁注入句柄 → 销毁池 → 关引擎 → 释放规则快照 → 删队列/设备。
// 幂等: 重复 quiesce/destroy 安全; init 部分失败回滚走同一对函数。
// ============================================================================
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
