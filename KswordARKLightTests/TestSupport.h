#pragma once

// 各验收测试套件共用的最小断言支撑。每个套件返回自己的失败计数，wmain 汇总。

#include <iostream>
#include <string>

namespace KswordTests {

class Suite final {
public:
    explicit Suite(const wchar_t* name) : name_(name) {}

    void expect(bool condition, const wchar_t* label) {
        ++checks_;
        if (!condition) {
            ++failures_;
            std::wcerr << L"FAIL [" << name_ << L"] " << label << L'\n';
            // 兜底：万一某个宽字符仍然转不出去（locale 不支持、控制台重定向到
            // 非 UTF-8 管道），流会被置 badbit 并从此静默吞掉**后续所有输出**，
            // 包括别的套件的失败和最终汇总。清掉状态，宁可这一行乱码也不能让
            // 一次转换失败把整份测试结果变成空白。
            clearIfBroken(std::wcerr);
        }
    }

    int failures() const { return failures_; }
    int checks() const { return checks_; }

    void report() const {
        std::wcout << L"  " << name_ << L": " << (checks_ - failures_) << L'/' << checks_
                   << L" checks passed\n";
        clearIfBroken(std::wcout);
    }

    static void clearIfBroken(std::wostream& stream) {
        if (!stream.good()) {
            stream.clear();
        }
    }

private:
    const wchar_t* name_;
    int failures_ = 0;
    int checks_ = 0;
};

} // namespace KswordTests

// 各验收套件入口。名字对应验收规范的模块字母。
// 新增套件时在这里声明，并在 wmain 里累加其失败计数。
int RunEvidenceContractTests();   // F
int RunCrossViewTests();          // X
int RunEntityGraphTests();       
int RunDumpFactsTests();         
int RunSnapshotCompareTests();   
int RunSecurityStateTests();     
int RunWfpTests();               
int RunTimelineTests();          
int RunImageIntegrityTests();    
int RunMemoryEvidenceTests();    
int RunInjectionSurveyTests();    // J：进程内存植入与完整性检查
int RunHvmEptSwitchTests();       // EPTP 切换后端（shared/driver，纯算术 + 状态机）
int RunHvmWatchTests();           // 首次访问监视（shared/driver，纯算术 + 状态机）
int RunDdmaPlanTests();           // DDMA 磁盘 DMA（shared/driver，ATA 寄存器编码 + 切片 + 门禁）
int RunNumericTextParseTests();   // 数值文本解析（shared/evidence，地址/数量两种默认进制）
int RunMemoryTamperCrossViewTests(); // 内存内容交叉视图（shared/evidence，多读取路径互比）
int RunDmaProcessOpPlanTests();      // DMA 进程操作计划（shared/evidence，空隙/备份/读回校验）

// 内存工作台逻辑层（shared/evidence/memory_workbench，Qt-free、Win32-free）。
// 套件名统一前缀 "MEMWB "，避免与 KswordARKLight 自己的 "M memory evidence" 撞名。
int RunMemwbSessionTests();           // 目标会话：身份键、内核地址判据、双代次陈旧判定
int RunMemwbOverlayTests();           // 暂存叠加层：补丁合并/拆分、基线保留、变更分类
int RunMemwbAddressExprTests();       // 地址表达式：十六进制默认、模块+偏移、解引用、溢出拒绝
int RunMemwbViewportTests();          // 虚拟滚动视口：行对齐/补空位、页缓存 LRU、线性选区
int RunMemwbInt3LedgerTests();        // int3 补丁账本：目标绑定、已含 0xCC 拒绝、逐条还原
int RunMemwbAddressBookTests();       // 统一地址簿：稳定 id、模块+RVA、序列化往返
int RunMemwbWriteTransactionTests();  // 写事务状态机：写前复核/回读、同意范围、模式切换守卫
int RunMemwbValueDecodeTests();       // 数据解释器：整数/浮点/指针/时间/GUID/字符串解码与编码往返
int RunMemwbByteSearchTests();        // 字节查找引擎：通配/大小写/UTF-16、分块对拍、回绕明示、取消
int RunMemwbTargetTrackerTests();     // 目标追踪器：身份键续跟、PID 复用判定、模块遍历与陈旧代次
int RunMemwbChannelGateTests();       // 通道闸门：读写通道能力判定、降级与拒绝原因
int RunMemwbWritePolicyTests();       // 写入策略：同意范围、保护页与内核地址写入门禁
int RunMemwbProcessMatchTests();      // 进程匹配：名称/路径/PID 过滤与排序
int RunMemwbModuleDirTests();         // 模块目录：模块区间索引、地址归属与模块+偏移反查
int RunMemwbSessionResolverTests();   // 会话地址解析：表达式在目标会话下求值、模块与解引用
int RunMemwbBaselineWindowTests();    // 基线窗口：基线保留、窗口滑动与变更对比
int RunMemwbEditJournalTests();       // 编辑日志：写入记录、撤销/重做与回读校验
int RunMemwbPageReaderTests();        // 页式只读游标：kPageBytes 对齐、跨页拼接、前缀/不可读语义
int RunMemwbIoByteStoreTests();       // IByteStore 适配器：把一次 I/O 结果映射成 AccessResult
int RunMemwbKernelMutationTests();    // 内核分步字节事务编排：Prepare/DryRun/Force/ReadBack 与单次回滚
int RunMemwbPatchStoreTests();        // IPatchByteStore 适配器：int3 补丁账本的读写落点

int RunProcessInformationTests();
int RunCallbackEnumerationTests();

int RunR3NetworkBackendTests();
