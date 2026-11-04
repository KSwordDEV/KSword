# NTOS 离线动态偏移核对

映像文件：1955；可比较：1950；无法匹配参考或读取失败：5。
参考来源：新版发布包 1950 个，F 盘散装导出 0 个。
字段候选与参考一致：41078；不一致：0；候选不可用：9395；参考缺失：207；两者均不可用：20。

同一 PE 的 machine、时间戳、映像大小、RSDS GUID/Age 和 SHA256 必须对应参考。生产访问器解码器原样编译；栈、保护和签名代码形态按驱动对应实现离线提取。结果为静态候选，不含驱动现场对象、容器和生命周期校验。新版包优先；未被新版包覆盖时使用身份及哈希一致的 F 盘导出。发布包 JSON SHA256：15b6510660ea0f211dff46318672d9bb7e0cd8bcd833b989de49016f31a560cf。

| 字段 | 一致 | 不一致 | 候选不可用 | 参考缺失 | 两者均无 |
|---|---:|---:|---:|---:|---:|
| EpActiveThreads | 500 | 0 | 1446 | 0 | 4 |
| EpCreateTime | 1946 | 0 | 0 | 4 | 0 |
| EpDebugPort | 1946 | 0 | 0 | 4 | 0 |
| EpExitStatus | 1946 | 0 | 0 | 4 | 0 |
| EpImageFileName | 1946 | 0 | 0 | 4 | 0 |
| EpInheritedFromUniqueProcessId | 1946 | 0 | 0 | 4 | 0 |
| EpJob | 1946 | 0 | 0 | 4 | 0 |
| EpPeb | 1946 | 0 | 0 | 4 | 0 |
| EpPriorityClass | 0 | 0 | 1946 | 0 | 4 |
| EpProtection | 1946 | 0 | 0 | 4 | 0 |
| EpSectionBaseAddress | 1946 | 0 | 0 | 4 | 0 |
| EpSectionSignatureLevel | 1800 | 0 | 146 | 4 | 0 |
| EpSecurityPort | 1946 | 0 | 0 | 4 | 0 |
| EpSignatureLevel | 1800 | 0 | 146 | 4 | 0 |
| EpUniqueProcessId | 1946 | 0 | 0 | 4 | 0 |
| EpWin32Process | 1946 | 0 | 0 | 4 | 0 |
| EpWin32WindowStation | 1946 | 0 | 0 | 4 | 0 |
| EpWow64Process | 0 | 0 | 1819 | 127 | 4 |
| EtCid | 1946 | 0 | 0 | 4 | 0 |
| EtStartAddress | 0 | 0 | 1946 | 0 | 4 |
| EtWin32StartAddress | 0 | 0 | 1946 | 0 | 4 |
| KtInitialStack | 1946 | 0 | 0 | 4 | 0 |
| KtProcess | 1946 | 0 | 0 | 4 | 0 |
| KtStackBase | 1946 | 0 | 0 | 4 | 0 |
| KtStackLimit | 1946 | 0 | 0 | 4 | 0 |
| PsLoadedModuleList | 1950 | 0 | 0 | 0 | 0 |

上述受检字段在发布包与对应旧导出中的参考值差异：0 条；逐映像逐字段明细见 final-results.jsonl。

以下映像未找到精确对应的发布包或 F 盘散装导出，未进行字段比较：
- ntoskrnl.exe.10.0.26100.8309，SHA256 `483f14bce87af1bede2f85cc084e8b99a9c84d7ff518c5fec136d16350e74090`
- ntoskrnl.exe.10.0.26100.8575，SHA256 `7933a9c9e110b785b1665f67028e55e03d437ad4333e51c6fe0fdbec6e305d29`
- ntoskrnl.exe.10.0.26100.9201，SHA256 `264b0f22d6515522612fb709d3d530ea7d5907c46ee298d4a5094fcb3dfe8da9`
- ntoskrnl.exe.10.0.28000.1812，SHA256 `b4f2e9233dfcaff50c9c76c4a3923dc6571b8461e74931c433a1d8d0390327a7`
- ntoskrnl.exe.10.0.28000.1896，SHA256 `89cdaee934c5f0cb4edf15e4ba36ffd4d564c8cc983df375628958f23a772eb6`

目录下另有 6 个版本目录没有任何 PE 文件：10.0.19041.1200、10.0.20348.2652、10.0.22621.4036、10.0.22621.4111、10.0.22621.4387、10.0.26100.3025。

注：无法从静态 PE 验证的动态链表、令牌、进程、线程、回调容器等现场解析不在上述字段覆盖范围。
