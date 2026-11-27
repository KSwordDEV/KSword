# Light 新 Release 既有项目只读验收

- 状态：**FAIL，首错后停止，不重跑**。
- 产品提交：`5ba974a93b4c373a393ce9740ed8c85f81cfacfa`。
- 新 Light SHA256：`F0AD50F57B911F7C06F9B9E37731986E5F57ED8B3FFAF4020917E709717F2413`。
- 采集未启动、CLI 未调用、未创建新 sample。
- 已回放 sample：`18141f17-b514-4526-b9bb-63924ea690bd`；既有归档 218 个原包，终止 Stored 序号 221。
- 首错：UIA 在实际 `写入与请求候选` TreeView 下找到 0 个 TreeItem，未找到 `行为规则/Behavior Rules` 根；Enter 原坐标和规则输入详情未执行。
- 归档中的 `NtQueryInformationProcess` 行数为 0/218；process-query 新字段为 **NOT COVERED**，不声称实时 Hook 覆盖。
- GUI exit 0，设置恢复，驱动 absent，无本轮自有进程残留。

原始证据：`traceback.txt`、`behavior-tree-uia.json`、`archive-loaded.bmp`、`archive-loaded.png`、`run.log`、`receipt.json`。
