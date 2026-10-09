#pragma once

// ==============================
// Framework.h
// 该头文件是 Framework 模块对外唯一入口：
// 1) 暴露日志等级、事件结构与日志管理器；
// 2) 暴露五个全局流式日志对象（dbg/info/warn/err/fatal）；
// 3) 暴露 eol 宏用于携带文件/行号/函数信息并触发一次日志提交；
// 4) 暴露 kProgress 任务进度管理器（kPro）。
// ==============================

#include <cstddef>    // std::size_t：用于修订号与容器索引。
#include <ctime>      // std::time_t：用于记录日志时间戳。
#include <mutex>      // std::mutex：用于日志容器线程安全。
#include <sstream>    // std::ostringstream：用于流式拼接日志文本。
#include <string>     // std::string：用于保存日志内容/文件名/函数名。
#include <unordered_map> // std::unordered_map：用于关联任务 PID 与 owner。
#include <unordered_set> // std::unordered_set：用于确保每个 owner 只注册一次清理回调。
#include <vector>     // std::vector：用于日志管理器内部存储。
#include <memory>     // std::shared_ptr：两种任务视图共享不可变快照。
#include <cstdint>    // std::uint64_t：任务轮次与终态展示期限。
#include <QMetaObject> // owner 析构连接在管理器销毁时统一解除。
#include <QString>    // QString：用于 Qt 字符串日志输出重载。

// Windows 平台下使用 GUID 作为事件唯一标识。
#include <guiddef.h>

// Ksword.h：统一包含 ksword/ 目录下的 Win32 工具封装（进程/字符串等）。
// 规范要求：Framework.h 作为全局入口，需要级联引入 Ksword.h。
#include "Ksword.h"
#include "Framework/StartupSplash.h"

class QObject;

// Logging core now lives in ksword/log/log.h and is re-exported by Ksword.h.
// Legacy names such as kLogEvent, kEventEntry, dbg/info/warn/err/fatal,
// GuidToString, LogLevelToString, FormatTimeToString and eol remain
// available through that reusable ksword module.

// 任务状态：LegacyCompleted 只表示旧调用已经结束，绝不猜测成功或失败。
enum class kProgressState
{
    Running,
    Waiting,
    LegacyCompleted,
    Success,
    Failure,
    Canceled
};

// IsProgressTerminal：判断已结束状态，供核心和两个视图使用同一规则。
inline bool IsProgressTerminal(const kProgressState state)
{
    return state != kProgressState::Running && state != kProgressState::Waiting;
}

// kProgressTask：单个进度任务的可视快照数据。
// 该结构用于 UI 渲染“当前操作”卡片列表。
struct kProgressTask
{
    int pid = 0;                             // 任务唯一 ID（由 add 返回）。
    std::string taskName;                    // 任务标题（如“任务1”）。
    std::string stepName;                    // 当前步骤（如“步骤2”）。
    int stepCode = 0;                        // 步骤状态码（保留字段，供业务自定义）。
    float progress = 0.0f;                   // 规范化进度值，范围 [0.0, 1.0]。
    bool hiddenInList = false;               // true 表示该任务卡片应从列表隐藏（如完成）。
    bool hideProgressBarTemporarily = false; // true 表示临时隐藏进度条（UI 选项弹窗期间）。
    bool retainedForReuse = false;           // true 表示终态后保留，供同一 owner 的周期任务再次使用。
    kProgressState state = kProgressState::Running; // 明确终态与等待状态，不从步骤文案推断。
    std::uint64_t generation = 1;            // 同一可复用任务的请求轮次。
    bool generationGuarded = false;          // 显式 beginCycle 后只接受携带轮次的更新。
    std::uint64_t visibleUntilMs = 0;        // 显式终态短暂展示期限，使用单调时钟。
};

// 两种显示端共享同一修订下的不可变任务集合，避免 revision 与数据分开读取。
struct kProgressSnapshot
{
    std::size_t revision = 0;                // 和 tasks 在同一把锁下读取的修订号。
    std::vector<kProgressTask> tasks;         // 已复制且不会再修改的任务记录。
};

// kProgress：进度条管理器。
// 对外能力：
// 1) add：新增任务卡片并返回 PID；
// 2) set：更新步骤与进度；
// 3) UI：阻塞弹出选项对话框，返回用户选择序号（从 1 开始）。
class kProgress
{
public:
    // 构造函数作用：
    // - 初始化 PID 自增计数与容器。
    kProgress();
    ~kProgress(); // 解除 owner 连接；局部管理器不能留下引用自身的回调。

    // add 作用：
    // - 新增一条任务记录并显示到任务卡片列表；
    // - 返回新任务的 PID，后续 set/UI 都用它定位任务。
    // 参数 taskName：任务名称（卡片标题）。
    // 参数 stepName：初始步骤文本。
    // 返回值：新任务 PID（大于 0）。
    int add(const std::string& taskName, const std::string& stepName);

    // add（owner 绑定版本）作用：
    // - 创建一次性任务，并在 owner 析构时自动移除；
    // - 适合异步 UI 操作，防止页面关闭后留下僵尸任务。
    // - 必须在 owner 所在线程登记；后台更新/finish 使用返回的任务 ID。
    int add(QObject* owner, const std::string& taskName, const std::string& stepName);

    // addReusable 作用：
    // - 创建可在完成后再次 set 的周期任务；
    // - owner 析构时仍会自动移除，避免跨页面生命周期泄漏。
    int addReusable(QObject* owner, const std::string& taskName, const std::string& stepName);

    // set 作用：
    // - 更新指定 PID 的步骤文本与进度；
    // - 当 progressValue 最终归一化到 1.0 时自动隐藏该任务卡片。
    // 参数 pid：目标任务 PID。
    // 参数 stepName：新的步骤文本。
    // 参数 stepCode：步骤状态码（业务保留字段）。
    // 参数 progressValue：
    // - 支持 [0,1] 比例值（如 0.7）；
    // - 也支持 [0,100] 百分值（如 70.0f，会自动转换到 0.7）。
    void set(int pid, const std::string& stepName, int stepCode, float progressValue);

    // finish：显式提交 Success/Failure/Canceled；未知任务、重复终态或非终态返回 false。
    bool finish(int pid, kProgressState state, const std::string& stepName, int stepCode = 0);

    // beginCycle：显式开启新轮次；返回令牌，后续必须调用携带 generation 的 set/finish。
    // 一次性任务不允许重启；旧可复用调用仍兼容，但无法识别无令牌的迟到结果。
    std::uint64_t beginCycle(int pid, const std::string& stepName);
    void set(int pid, std::uint64_t generation, const std::string& stepName, int stepCode, float progressValue);
    bool finish(int pid, std::uint64_t generation, kProgressState state,
        const std::string& stepName, int stepCode = 0);

    // SnapshotWithRevision：返回可跨视图共享的只读快照；相同修订复用同一 shared_ptr。
    std::shared_ptr<const kProgressSnapshot> SnapshotWithRevision() const;
    // expireVisibleTerminals：由 UI feed 调用，到期仅隐藏显式终态，历史仍保留。
    void expireVisibleTerminals();

    // UI（vector 版本）作用：
    // - 阻塞弹出选项对话框；
    // - 对话框显示期间临时隐藏该 PID 的进度条，选择结束后恢复。
    // 参数 pid：目标任务 PID。
    // 参数 prompt：对话框提示文本。
    // 参数 options：按钮选项数组（按顺序映射返回序号）。
    // 返回值：
    // - 1..N：用户选择了第几个选项；
    // - 0：用户取消或无可用选项。
    int UI(int pid, const std::string& prompt, const std::vector<std::string>& options);

    // UI（可变参版本）作用：
    // - 语法糖重载，支持 UI(pid, "提示", "选项A", "选项B", ...)。
    // 参数 pid/prompt：含义同上。
    // 参数 options：可变参数选项列表，需可构造成 std::string。
    // 返回值：同 vector 版本。
    template <typename... TOptions>
    int UI(int pid, const std::string& prompt, const TOptions&... options)
    {
        // 把可变参数统一收敛为 vector，复用主实现。
        const std::vector<std::string> optionList{ std::string(options)... };
        return UI(pid, prompt, optionList);
    }

    // Snapshot 作用：
    // - 返回当前所有任务的快照副本（含隐藏标记）。
    // 返回值：任务数组副本。
    std::vector<kProgressTask> Snapshot() const;

    // Revision 作用：
    // - 每次 add/set/UI 状态切换都会递增；
    // - UI 可用此值判断是否需要刷新。
    // 返回值：当前修订号。
    std::size_t Revision() const;

private:
    // normalizeProgress 作用：
    // - 统一把进度值转换为 [0,1]；
    // - 自动支持“70.0f”这类百分值写法。
    // 参数 rawProgress：原始进度。
    // 返回值：归一化进度。
    static float normalizeProgress(float rawProgress);

    // addInternal 作用：集中创建任务并可选绑定 owner 生命周期。
    int addInternal(
        QObject* owner,
        const std::string& taskName,
        const std::string& stepName,
        bool retainedForReuse);

    // pruneTerminalHistoryLocked 作用：锁内只保留有界的一次性终态历史。
    void pruneTerminalHistoryLocked();

    // removeTasksOwnedBy 作用：owner 析构时批量删除其全部任务与绑定记录。
    void removeTasksOwnedBy(QObject* owner);

    // setProgressBarHiddenForUi 作用：
    // - 在 UI 弹窗前后切换“临时隐藏进度条”状态。
    // 参数 pid：目标任务 PID。
    // 参数 hidden：true 隐藏，false 恢复。
    void setProgressBarHiddenForUi(int pid, bool hidden, std::uint64_t generation);
    // setInternal/finishInternal：锁内验证轮次，阻止迟到更新覆盖新轮或已完成状态。
    void setInternal(int pid, std::uint64_t generation, bool guarded,
        const std::string& stepName, int stepCode, float progressValue);
    bool finishInternal(int pid, std::uint64_t generation, bool guarded,
        kProgressState state, const std::string& stepName, int stepCode);

private:
    mutable std::mutex m_mutex;             // 保护任务容器与修订号的线程锁。
    std::vector<kProgressTask> m_tasks;     // 进度任务容器。
    std::unordered_map<int, QObject*> m_taskOwners; // 记录 owner 绑定，任务删除时同步清理。
    std::unordered_set<QObject*> m_boundOwners;     // 每个存活 owner 最多保留一个 destroyed 回调。
    std::unordered_map<QObject*, QMetaObject::Connection> m_ownerConnections; // 销毁时解除绑定。
    int m_nextPid = 1;                      // 下一个可分配 PID（自增）。
    std::size_t m_revision = 0;             // 任务数据修订号。
    mutable std::shared_ptr<const kProgressSnapshot> m_sharedSnapshot; // 当前修订的共享快照缓存。
};

// Global progress manager for UI and business code.
// Logging globals are declared by ksword/log/log.h via Ksword.h.
extern kProgress kPro;
