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
int RunHvmEptSwitchTests();       // EPTP 切换后端（shared/driver，纯算术 + 状态机）
