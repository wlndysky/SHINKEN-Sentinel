# SHINKEN WFP Demo — 真实 WDK 工程(wdk/)

本目录是**真实 Windows 驱动构建**入口, 与仓库既有的 shim/LLVM/host 验证
(`build.bat`, `tools/check_*.py`, `tests/run_tests.bat`)**完全分离**:

| 构建 | 入口 | 头文件 | 产物 |
|---|---|---|---|
| LLVM/host 验证 | `build.bat` / `tests\run_tests.bat` | `shim/`(定义 `SHINKEN_HOST_SHIM`) | `out/*.ll`, host 测试 `.exe` |
| 真实 WDK 构建(本目录) | `wdk\shinken_wfp.vcxproj` | 真实 WDK(`ntddk.h;ndis.h;fwpsk.h;fwpmk.h;wdf.h`, 经 `shinken_wfp.props` 强制包含) | `wdk\build\<cfg>\shinken_wfp.sys/.pdb/.inf/.cat` |

两条线共享同一份现代核心源码(18 个 `.c`), 但**绝不共享头文件**;
仅 `wdk/` 中列出的现代核心源文件参与真实构建。

## 前置(门控, 未满足则不得构建/安装)

1. **Visual Studio 2022**(或 Build Tools)+ "使用 C++ 的桌面开发";
2. **Windows Driver Kit (WDK) 10.0.26100.x** + VS 扩展
   (`WindowsKernelModeDriver10.0` 工具集);
3. x64; KMDF target version **1.25**(`KMDF_VERSION_MAJOR/MINOR`);
4. 安装驱动前(独立门控, 需用户逐项确认):
   - `infverif` 通过(默认规则集; 非 PnP 旧式安装段不做 D-INF 声明);
   - 测试签名(`makecert`/`New-SelfSignedCertificate` + `signtool sign`),
     **测试签名不是生产签名**;
   - `bcdedit /set testsigning on` + 重启(先记录原始 bcdedit);
   - VMware 快照 `before-shinken-wfp-real-driver-test-<日期>-<时间>`;
   - Driver Verifier 原始配置已记录(`verifier /query`)。

## 构建

```bat
msbuild wdk\shinken_wfp.vcxproj /m /p:Configuration=Release /p:Platform=x64 /v:minimal
```

* W4 + WX(警告即错误); `RunCodeAnalysis=true`(PREFast `/analyze`,
  NativeRecommendedRules); SAL 由真实 WDK 头提供;
* 构建后自动执行: `stampinf`(日期/版本) → `Inf2Cat`(生成
  `shinken_wfp.cat`); 需要 `$(WDKBinRoot)x86\` 下的 WDK 工具, 缺失即报错
  (路径回退见 `shinken_wfp.props`);
* 产物: `wdk\build\Debug\` / `wdk\build\Release\` 下的
  `shinken_wfp.sys / .pdb / .inf / .cat`。

## 统一身份(改一处必须同步全部)

| 项 | 值 | 定义点 |
|---|---|---|
| 服务名 | `ShinkenWfp` | `wdk\shinken_wfp.inf` |
| 设备/符号链接 | `\Device\ShinkenWfp` / `\??\ShinkenWfp`(`\\.\ShinkenWfp`) | `driver\device.c` |
| 设备 SDDL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)` | `driver\device.c` |
| 设备接口 | 无(非 PnP 控制设备无 PDO, `WdfDeviceCreateDeviceInterface` 必返 `STATUS_NO_SUCH_DEVICE`; 用户态打开路径为 `\\.\ShinkenWfp`) | — |
| provider/sublayer/callout/filter GUID | 见清单 | `wfp\wfp_guids.h`(唯一) |

**GUID 档位: `test-2026-09-12`(测试 GUID, 非生产)。** 全部 GUID 单一定义于
`wfp\wfp_guids.h`, 清单在 `wdk\guid_registry.json`, INF 经
`AddReg` 登记到 `HKLM\SYSTEM\CurrentControlSet\Services\ShinkenWfp\Parameters\Wfp`
供诊断核对。更换档位 = 同一提交内改 `wfp_guids.h` + `guid_registry.json` +
`shinken_wfp.inf` 三处; 禁止零 GUID, 禁止测试/生产混用。

## 安装/卸载(全部门控步骤完成之后)

```bat
rem 入 driver store(仅暂存, 不创建服务)
pnputil /add-driver shinken_wfp.inf /install
rem 非 PnP: 服务创建走 DefaultInstall 段
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\shinken_wfp.inf
sc query ShinkenWfp
sc start ShinkenWfp
```

卸载顺序: `sc stop ShinkenWfp` → 确认 `netsh wfp show state` 无残留 →
`InstallHinfSection` 反向卸载或 `sc delete ShinkenWfp`(仅确认是本任务服务后)。

## 当前状态

真实 WDK 编译(x64 Release/Debug)、测试签名、infverif(0 error)、安装、
真实内核加载、真实流量规则行为、IOCTL 走带、Driver Verifier 均已通过;
完整证据与未覆盖项见 docs/REAL_KERNEL_VALIDATION_20260913.md。
