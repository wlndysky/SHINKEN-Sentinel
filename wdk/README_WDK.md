# SHINKEN Sentinel WDK 构建

本目录提供 x64 KMDF 驱动工程，使用真实 WDK 头文件。它与仓库根目录 `build.bat` 的 shim/LLVM IR 路径分离，不依赖未随仓库发布的测试或检查脚本。

## 前置条件

- Visual Studio 2022 或 Build Tools，安装 C++ 工具链。
- Windows SDK、WDK 10.0.26100.x 及对应集成组件，提供 `WindowsKernelModeDriver10.0` 工具集。
- 工程目标为 x64、KMDF 1.25，支持 Debug 和 Release 配置。

## 构建命令

在仓库根目录的 VS 开发者命令提示符中执行：

```bat
msbuild wdk\shinken_wfp.vcxproj /m /p:Configuration=Release /p:Platform=x64 /v:minimal
msbuild wdk\shinken_wfp.vcxproj /m /p:Configuration=Debug /p:Platform=x64 /v:minimal
```

工程启用 W4、警告视为错误和原生代码分析。构建后执行 `stampinf` 与 `Inf2Cat`；工具路径由 [shinken_wfp.props](shinken_wfp.props) 解析，缺失时构建报错。

输出位于 `wdk/build/Release/` 或 `wdk/build/Debug/`，包含驱动、调试符号、INF 和目录文件。工程关闭自动签名；生成 `.cat` 不代表已经签名，也不代表可以直接加载。

## 设备身份

服务名为 `ShinkenWfp`，用户态设备路径为 `\\.\ShinkenWfp`。设备名和访问控制定义在 [device.c](../driver/device.c)，服务安装定义在 [shinken_wfp.inf](shinken_wfp.inf)。

WFP GUID 定义见 [wfp_guids.h](../wfp/wfp_guids.h)，登记清单见 [guid_registry.json](guid_registry.json)。修改身份时需核对头文件、清单和 INF 的一致性。

## 使用边界

这是研究框架的构建入口，不是已签名驱动的分发包。签名、安装和加载是独立操作，本文件不提供自动部署流程，也不声称这些操作已经在读者的环境中验证通过。
