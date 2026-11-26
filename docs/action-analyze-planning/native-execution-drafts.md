# 原生执行归档到执行集合草稿

Qt入口为“监控 → 行为分析 → 总览 → 归档关系”，Light入口为“监控 → ActionAnalyze → 工程与采集 → 归档关系”。在原生执行一致性候选或独立历史上选择来源，点击“准备地址草稿”或“准备范围草稿”，加入本端尚未启动的执行集合目录。表单输入保留，集合不自动开始；重复PID、16成员上限或活集合拒绝接收，不替换已有站点。载入或移除保存草稿仍走原入口。

两种动作只接受已核验v3原生文档中的私有执行绑定。进程身份来自原PID＋创建FILETIME，单地址来自实际指令起点；范围必须是原绑定已纳入、包含该指令的NX范围，不自动对齐、扩页或合并。模块、写关注、旧档缺绑定、缺实际范围均不能冒充本项输入。来源项目、采样、raw-native段号及摘要留在原字段详情／文本详情中，搜索、复制和导出使用同一份来源。新启动仍由原owner重新核对实例及私有内存；历史记录不授当前授权或控制票据。

CLI使用同一转换：

```text
KswordCLI.exe analyze execution draft --project PATH --sample UUID --ordinal N --json
KswordCLI.exe analyze execution draft --project PATH --sample UUID --ordinal N --range --sites-only --json
```

默认返回来源和`sitesFile`。`--sites-only`只返回原`execution-group --sites`接受的`{schemaVersion:1,sites:[...]}`对象；保存为无BOM UTF-8文件后可显式启动或通过原`members-append`追加。段号默认1、上限4096；本命令只读、不创建会话、不附加进程。

页面类型：总览关系树＋共享工具行，目标为ParameterWorkspace参数执行页＋None管理清单＋StructuredFieldView／Light原生文本。对照原写入停点候选准备、执行集合站点目录及其共享组件，不增加窗口、owner、线程或轮询。深浅主题、窄窗、键盘、复制导出、正式构建及真实GUI本批尚未执行；源码接线不能视为运行验收通过。

本功能只解决已存在执行证据的参数重用。用户最新要求的“API发现跨进程行为后自动解析私有范围并接管下一目标”另行实施，不能将手动历史草稿算成自动接管完成。
