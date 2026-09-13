@echo off
REM build.bat - shinken_wfp_demo modern driver build. Static and IR verification.
REM Two stages. NOT a real WDK build (no WDK/MSBuild on this machine); see
REM docs/ARCHITECTURE.md "verification boundary":
REM   A) per-module clang syntax check (shim/wdk_shim.h, gnu89)
REM   B) LLVM IR: per-module -emit-llvm (-fdebug-compilation-dir=. strips local
REM      paths), llvm-link merge, opt -O2 -> out/shinken_driver_O2.ll (+_opt.ll)
REM IR results feed tools/check_ir.py (dead code/undefined symbols/optnone/
REM DriverEntry count). They do NOT replace a real WDK build or kernel tests.
setlocal
cd /d "%~dp0"
if "%LLVM_DIR%"=="" set LLVM_DIR=%ProgramFiles%\LLVM
set CLANG=%LLVM_DIR%\bin\clang.exe
set OPT=%LLVM_DIR%\bin\opt.exe
set LLVMLINK=%LLVM_DIR%\bin\llvm-link.exe
set FLAGS=-target x86_64-pc-windows-msvc -std=gnu89 -DSHINKEN_HOST_SHIM -fdebug-compilation-dir=. -Wno-unknown-attributes -Wno-deprecated-non-prototype -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -I . -I shim -include shim\wdk_shim.h -include shim\wfp_layers.h
set MODULES=runtime\rundown.c runtime\runtime.c runtime\lifecycle.c telemetry\event_queue.c rules\rule_match.c rules\rule_store.c rules\rule_engine.c control\ioctl.c wfp\wfp_guids.c wfp\wfp_objects.c wfp\wfp_callouts.c wfp\wfp_manager.c packet\classify.c packet\injection.c packet\flow_context.c packet\packet_helpers.c driver\device.c driver\driver.c

if not exist out\ir mkdir out\ir
set FAILED=
for %%M in (%MODULES%) do (
  echo [syntax] %%M
  %CLANG% %FLAGS% -fsyntax-only %%M || set FAILED=1
)
if defined FAILED (echo BUILD FAILED & exit /b 1)

for %%M in (%MODULES%) do (
  %CLANG% %FLAGS% -O2 -flto=thin -emit-llvm -S %%M -o out\ir\%%~nM.ll || set FAILED=1
)
if defined FAILED (echo BUILD FAILED & exit /b 1)


setlocal EnableDelayedExpansion
set IRFILES=
for %%M in (%MODULES%) do set IRFILES=!IRFILES! out\ir\%%~nM.ll
echo [llvm-link] out\shinken_driver_O2.ll
%LLVMLINK% -S !IRFILES! -o out\shinken_driver_O2.ll || (echo BUILD FAILED & exit /b 1)
echo [opt -O2] out\shinken_driver_O2_opt.ll
%OPT% -O2 -S out\shinken_driver_O2.ll -o out\shinken_driver_O2_opt.ll || (echo BUILD FAILED & exit /b 1)
endlocal
echo BUILD OK
endlocal
