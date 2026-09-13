#pragma once
// shim 侧 initguid.h: 真实 WDK 中该头使后续 DEFINE_GUID 展开为定义;
// shim 的 DEFINE_GUID 恒为 static const(见 shim/guiddef.h), 无需开关。
#include "wdk_shim.h"
