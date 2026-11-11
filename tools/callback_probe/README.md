# CLI 回调注销受控夹具

该非 PnP WDM 驱动只为自己注册一个传统进程通知，不创建设备、线程或持久规则。`Test-CallbackProbe.ps1` 要求调用方已经加载配套 KswordARK，使用独立随机 SCM 服务加载该夹具；只有在加载前确认同名模块不存在、加载后确认唯一模块基址和大小，再以地址范围找到唯一属于夹具的进程回调，才调用 `callback remove-row`。脚本随后在完整回调快照中确认该函数消失，最后停止并删除自己创建的服务。卸载例程只尝试注销本驱动自己的通知。

使用 x64 WDK 构建 `KswordCallbackProbe.vcxproj`，为测试机采用其既有测试签名流程签名；脚本不修改系统策略、信任存储或 KswordARK 服务。将配套 CLI、运行库和签名后的 `KswordCallbackProbe.sys` 复制到测试机后运行：

```powershell
./Test-CallbackProbe.ps1 -Cli <配套CLI路径> -ProbeSys <签名后的KswordCallbackProbe.sys路径>
```

如果枚举不完整、同名模块已存在、目标并非唯一候选或当前动态数据不支持，脚本停止而不移除任何回调。CLI 超时表示动作状态未知，不自动重试；如果子进程仍在运行，则保留专用测试服务并报告名称，待确认后手动清理。脚本只验证该自有进程回调，不证明其他类别或系统版本的注销能力。
