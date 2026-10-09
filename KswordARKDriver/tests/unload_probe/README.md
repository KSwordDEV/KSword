# 强卸载对照驱动

`KswordUnloadProbe.sys` 是专用非 PnP WDM 驱动，只有 DriverEntry 和 DriverUnload，不创建设备、回调、线程或异步工作。它用于区分 Beep 的系统占用拒绝与卸载通路本身失败。它不链接进生产驱动、不随主程序自动加载；本轮只构建，未签名、安装或加载。

构建使用仓库要求的 x64 MSBuild/HostX64：

```powershell
& $msbuild 'KswordARKDriver/tests/unload_probe/KswordUnloadProbe.vcxproj' /t:Build `
  /p:Configuration=Release /p:Platform=x64 `
  /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 `
  /m:1 /v:minimal
```

后续允许实测时，在专用来宾为该产物使用来宾现有测试签名流程，以 SCM 服务名 `KswordUnloadProbe` 注册。先验证普通 SCM 停止能够卸载，再重新加载，用 `kernel force-unload-driver --driver \Driver\KswordUnloadProbe --timeout-ms 5000` 保存回执，立即读取 `log --max-frames 256`。成功必须同时满足 CLI 退出码 0、响应 UNLOADED、DriverObject 查询不到且模块枚举中不存在。若要比较 `--flags 0x200`，重新加载后单独执行，记录是否仅调用了卸载例程及闭环验证结果；当前 CLI 对 UNLOAD_ROUTINE_CALLED 返回 6，明确输出 fullUnloadConfirmed=0，并只读回查 DriverObject 是否仍存在。不得把例程调用完成当成镜像已卸载。

实验结束由测试操作者停止和删除该专用服务。不要用 Beep 或其他系统驱动作为这个成功对照。

用户提供的探针回执已确认：默认 flags 返回 UNLOADED，随后对象和模块消失；显式 `0x200` 返回 UNLOAD_ROUTINE_CALLED，随后对象和模块仍在。该证据支持完整卸载路径可用，不是本次 agent 执行的实测。
