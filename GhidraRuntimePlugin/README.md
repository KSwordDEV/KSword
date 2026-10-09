# Ghidra 反编译后端插件

该插件为共用 HEX、反汇编、文本组件提供 C 伪代码后端。它是 `plugin_type=backend`，只注册 `decompiler` 能力；不会创建新的插件 Tab，也没有可执行插件入口、默认命令或安装脚本入口。安装阶段不启动 Java、Ghidra 或样本。

在 KSword 的插件商城安装 Ghidra 后端后，组件使用插件目录中的 Ghidra 和 JDK，不需要设置系统 Java 或手工选择后端目录。插件通过现有插件管理器安装和更新；安装目录通过验证后即可使用。高级用户仍可在 C 页使用自定义 Ghidra 目录和 Java 环境；这属于显式覆盖。

## 上游直下载分发

该插件现在使用通用 `upstream-assets` 协议。`KSwordDEV/Plugins` 维护版本、官方资源 URL、
SHA-256、解压布局和清单，客户端直接从 Ghidra/Temurin 的官方 GitHub Release 下载完整 ZIP。
协议和维护流程见 [插件上游分发协议](../docs/插件上游分发协议.md)。初始市场条目见
[`marketplace-entry.json`](marketplace-entry.json)，客户端目录快照见
[`PluginMarketplace/catalog.json`](../PluginMarketplace/catalog.json)。在线同 ID 条目优先。

安装与更新由用户点击触发；不自动追踪上游最新版本，也不进入普通 ZIP 的自动更新队列。
仅更新 JDK 时，也应递增插件包 `version`。下面是初始条目与历史离线构包的参考版本。

| 组件 | 固定版本 | 官方 ZIP SHA-256 |
| --- | --- | --- |
| Ghidra | 12.0.4 | `c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120` |
| Eclipse Temurin JDK | 21.0.12.1+1，Windows x64 | `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` |

生产安装读取市场的分发计划；`RuntimeProfile.cpp` 和 `runtime-assets.json` 中的参考配置只供历史包兼容及离线构包使用。下载校验、完整解压、结构验证全部成功后才推广暂存目录；旧插件不会被部分下载替换。

安装后的布局：

```text
plugin/ghidra/
  plugin.json
  upstream-install.json
  LICENSE.txt
  NOTICE.md
  KSword-LICENSE.txt
  UPSTREAM-GHIDRA-NOTICE.txt
  runtime/ghidra_12.0.4_PUBLIC/
  jdk/jdk-21.0.12.1+1/
```

`RuntimeProfile::validateDirectory` 验证固定后端类型、能力和清单声明的相对路径，拒绝入口点/Tab/命令字段、目录逃逸、丢失许可、版本与清单不一致和非 amd64 的 Java/反编译器程序。后端从已验证的安装清单读取实际路径。Ghidra 的完整 `licenses/`、`GPL/`、模块许可，以及 JDK 的完整 `legal/`、NOTICE、release、Java 源码包均随官方文件树保留。历史离线包仍使用 `runtime-assets.json`。

## 许可证

原始 KSword 元数据、运行环境配置和安装胶水保持仓库现有的 KSword Community Source License 1.6，完整文本复制为 `KSword-LICENSE.txt`。没有把 KSword 代码改成 Apache 或 GPL。

Ghidra、JDK 与第三方载荷保留各自的许可证。`LICENSE.txt` 包含 Ghidra 的完整 Apache 2.0、JDK 的完整 GPL v2 + Classpath Exception、额外许可说明和 Temurin 通知。各组件的原始通知仍保留在完整运行环境中，主程序许可证不替代这些独立许可，也不限制它们授予的权利。Ghidra 官方二进制 ZIP 没有根 NOTICE 文件，因此另外保存官方源码标签中的原始 NOTICE 为 `UPSTREAM-GHIDRA-NOTICE.txt`。

应用安装器直接从原发布者下载未修改的官方 ZIP，用于用户本机安装。若今后重新发布合并后的二进制插件包，发布者还需满足各组件的对应源码提供义务；JDK 的 `lib/src.zip` 只包含 Java 源码，不等于完整 HotSpot 原生源码。固定 JDK 的源码标签、源码提交和构建提交已记录在 `NOTICE.md`，不以一个下载链接代替重新分发时的源码义务。

## 离线构包与验证

```powershell
python GhidraRuntimePlugin/package.py `
  --ghidra-archive .codex-tmp/decompiler-runtime/ghidra-12.0.4.zip `
  --jdk-archive .codex-tmp/decompiler-runtime/jdk21.zip `
  --inventory-only

python GhidraRuntimePlugin/package.py `
  --ghidra-archive .codex-tmp/decompiler-runtime/ghidra-12.0.4.zip `
  --jdk-archive .codex-tmp/decompiler-runtime/jdk21.zip `
  --output .codex-tmp/ghidra-plugin-package
```

脚本先校验官方 SHA-256、压缩与展开上限、路径、重复项和链接，然后创建全新的输出目录，不删除或覆盖已有目录。它完整保存两个 ZIP 的全部文件并生成逐文件 SHA-256 及许可清单；可用 `--zip` 指定输出目录之外的全新 ZIP 路径，生成排序和时间戳固定的本机离线包。脚本不会发布或镜像二进制。

`tools/generate_profile_metadata.py` 用固定的原始运行环境和仓库 LICENSE 生成源清单、组合许可及 C++ 许可数据；运行环境默认位于 `.codex-tmp/decompiler-runtime/`。`tests/profile_probe.cpp` 验证实际 QtCore 元数据写入和包目录。路径对抗回归：`python GhidraRuntimePlugin/tests/test_package_paths.py`。

2026-10-08 已对两个官方固定 ZIP 完成 SHA 和完整提取验证：6,996 个原始文件、498 个许可/模块通知文件全部保留；实际 QtCore 包目录验证通过。安装器与主程序 GUI 的执行验证另由对应测试宿主记录。
