# 秦剑 / SHINKEN Sentinel：Windows 内核网络策略与生命周期安全研究框架

## 缘起

几年前，我曾经写下“基于恶意 IP 流量分析检测系统研究”这份大学生创新创业大赛项目计划书。那时的原始代码并不成熟，结构混乱，充满临时方案和无法落地的设想。它更像一段年轻时期留下的技术草稿，而不是一个真正可以长期维护的系统。

多年以后，这个项目重新回到我的视线里。借助新一代工具协作与反复审阅，我没有继续修补旧代码，而是从生命周期、并发模型和内核边界重新开始设计，让它从一份几乎无法维护的早期遗留，逐步变成一个有清晰责任边界的现代 Windows WFP 框架。

## 设计思路

Shinken Sentinel 不以堆叠规则为目标，而是试图回答一个更基础的问题：内核中的每一次网络决策，能否被解释、被约束，并在需要时安全地撤销？

因此，规则管理与网络分类被刻意分开。控制面只负责校验、版本和发布；数据面只读取不可变快照，在 WFP classify 热路径中完成匹配和裁决。新规则发布不会修改正在使用的快照，读者退出后旧快照才进入回收。

同样的原则也适用于生命周期。WFP 对象、流上下文、注入句柄、事件、线程和用户请求都有明确的所有者。停止时先关闭生产者，再注销回调、排空引用、等待线程退出，最后销毁对象；任何无法证明安全的清理步骤，都会阻止继续卸载，而不是伪装成成功。

这套设计不假设回调“很短”，也不假设卸载时“不会再进来”。内核回调可能在不同 IRQL、线程和时间到达，所以系统使用 rundown、引用计数、事件和显式状态转换建立可验证的会合点。用户态只通过版本化 IOCTL 进入，长度、版本、权限、溢出和状态转换都在内核边界重新验证。

新的模块边界围绕责任建立：`driver/` 负责入口，`runtime/` 负责生命周期，`wfp/` 负责平台对象，`rules/` 负责策略，`packet/` 负责数据路径，`control/` 负责控制协议。无法解释的早期行为被舍弃，而不是继续复制。

## 当前状态

单一 KMDF 非 PnP 驱动 + 六层 WFP callout(ALE 裁决 + 流跟踪)+ 快照
规则引擎 + 版本化 IOCTL 控制面 + 遥测事件队列，已实现并通过真实内核
验证(见“验证边界”)。未实现: REDIRECT/INSPECT 动作与注入提交路径;
ifIndex/SID 规则条件保留且不支持(验证直接拒绝, 详见 docs/RULE_ENGINE.md)。

## 模块

| 目录 | 职责 |
|---|---|
| `driver/` | DriverEntry/EvtDriverUnload + 控制设备/ACL |
| `runtime/` | 生命周期终态机、rundown、注入门、阻断原因历史 |
| `wfp/` | engine/provider/sublayer/callout/filter 安装与拆除状态机 |
| `rules/` | 规则快照存储、评估、匹配、RATE_LIMIT 令牌桶 |
| `packet/` | classify 热路径、注入、流上下文 |
| `control/` | IOCTL 协议与分发 |
| `telemetry/` | 事件队列(生产者门 + 容量丢弃) |
| `shim/` | 最小 WDK 垫片(仅 IR/宿主验证用) |

详细设计: docs/ARCHITECTURE.md、docs/UNLOAD_SAFETY.md、
docs/WFP_LIFETIME.md、docs/RULE_ENGINE.md、docs/THREAT_MODEL.md。

## 构建
- 宿主验证(本仓库默认): `build.bat`(clang → LLVM IR)+
  `tests\run_tests.bat`(宿主失败注入测试); 头文件走 `shim/`。
- 真实 WDK 构建: `msbuild wdk\shinken_wfp.vcxproj /m /p:Configuration=Release /p:Platform=x64`
  (前置、签名、安装门控见 wdk/README_WDK.md)。

## 验证边界

clang 语法检查(shim)+ LLVM IR + 宿主失败注入测试覆盖状态机/协议/
并发交错/回滚/裁决语义; 真实 WDK 编译、真实内核加载、真实流量规则行为、
IOCTL 走带与 Driver Verifier 的实测证据见
docs/REAL_KERNEL_VALIDATION_20260913.md。SDV/HLK 未执行。

## 名称

中文名称：**秦剑**。英文名称：**SHINKEN Sentinel**。

“秦剑”保留项目最初的中文来意；`SHINKEN` 并非“秦剑”的严格音译，而是借用了日语 `真剣`（しんけん）的另一层意味：真正的剑，也意味着认真、郑重。两个名字语源不同，却共同提醒这个项目：网络裁决、内核生命周期和每一次失败处理，都必须真实、准确，不能靠想象蒙混过去。

代码兼容名仍为 `SHINKEN WFP`，以保持现有服务、协议和内核对象身份的连续性。
