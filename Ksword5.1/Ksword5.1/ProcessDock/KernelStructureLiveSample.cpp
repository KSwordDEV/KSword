#include "KernelStructureLiveSample.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"

#include <QDateTime>
#include <QStringList>
#include <QTimeZone>

namespace ks::ui::kernelstructure
{
    namespace
    {
        // 输入 Win32 创建时间，输出与协议一致的 100ns FILETIME 整数。
        std::uint64_t FileTimeValue(const FILETIME& value)
        {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) | value.dwLowDateTime;
        }

        // 输入可选持有句柄；无句柄时由新协议验证完整身份，有句柄时必须仍存活。
        bool HandleStillRunning(const ksword::ark::DriverHandle& handle)
        {
            return !handle.isValid() || ::WaitForSingleObject(handle.native(), 0) == WAIT_TIMEOUT;
        }

        // 输入内核采样时刻，输出带毫秒精度和 Z 后缀的 UTC 文本，禁止以 GUI 发布时刻代替。
        QString SampleTime(const std::uint64_t value)
        {
            constexpr std::uint64_t epoch = 116444736000000000ULL; // FILETIME 与 Unix 纪元的 100ns 差。
            if (value < epoch)
            {
                return QString::number(value);
            }
            return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>((value - epoch) / 10000ULL),
                QTimeZone::UTC).toString(Qt::ISODateWithMs);
        }
    }

    // 调用入口提供 PID/TID 和已知创建时间；返回共享冻结目标，失败原因保存在 diagnostic。
    std::shared_ptr<const LiveTarget> CaptureLiveTarget(const std::uint32_t pid,
        const std::uint64_t processCreationTime, const std::uint32_t tid, const std::uint64_t threadCreationTime)
    {
        auto target = std::make_shared<LiveTarget>(); // GUI 与在途工作共享同一组冻结句柄及创建时间。
        target->request.version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION;
        target->request.objectType = tid ? KSWORD_ARK_STRUCTURE_SAMPLE_ETHREAD : KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS;
        target->request.processId = pid;
        target->request.threadId = tid;
        target->request.processCreationTime100ns = processCreationTime;
        target->request.threadCreationTime100ns = tid ? threadCreationTime : 0;
        target->process.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));

        // 已有精确创建时间时，受保护进程无 R3 句柄仍可交给新协议复核；缺失时间不能猜测。
        FILETIME created{}; // 当前句柄所指对象的真实创建时间。
        FILETIME exited{}; // GetProcessTimes/GetThreadTimes 必须提供的退出时间输出。
        FILETIME kernel{}; // 时间 API 的内核累计时间占位输出。
        FILETIME user{}; // 时间 API 的用户累计时间占位输出。
        if (target->process.isValid())
        {
            if (!::GetProcessTimes(target->process.native(), &created, &exited, &kernel, &user) ||
                (processCreationTime && processCreationTime != FileTimeValue(created)))
            {
                target->diagnostic = QStringLiteral("无法复核冻结的进程创建时间；未执行采样");
                return target;
            }
            target->request.processCreationTime100ns = FileTimeValue(created);
        }
        if (!target->request.processCreationTime100ns)
        {
            target->diagnostic = QStringLiteral("缺少进程创建时间且无法获取原进程句柄；未执行采样");
            return target;
        }

        // 同时核对线程所有者和创建时间，不能用已回收 TID 请求另一个进程的线程。
        if (tid)
        {
            target->thread.reset(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
            if (target->thread.isValid())
            {
                if (::GetProcessIdOfThread(target->thread.native()) != pid ||
                    !::GetThreadTimes(target->thread.native(), &created, &exited, &kernel, &user) ||
                    (threadCreationTime && threadCreationTime != FileTimeValue(created)))
                {
                    target->diagnostic = QStringLiteral("线程所有者或冻结的创建时间不匹配；未执行采样");
                    return target;
                }
                target->request.threadCreationTime100ns = FileTimeValue(created);
            }
            if (!target->request.threadCreationTime100ns)
            {
                target->diagnostic = QStringLiteral("缺少线程创建时间且无法获取原线程句柄；未执行采样");
                return target;
            }
        }
        if (!pid || !LiveTargetRunning(*target))
        {
            target->diagnostic = QStringLiteral("冻结的目标已退出或无法复核存活状态；未采用本次采样");
        }
        return target;
    }

    // 输入冻结目标；只检查当前持有句柄与身份前提，不重绑已回收的 PID/TID。
    bool LiveTargetRunning(const LiveTarget& target)
    {
        return target.diagnostic.isEmpty() && target.request.processCreationTime100ns &&
            (!target.request.threadId || target.request.threadCreationTime100ns) &&
            HandleStillRunning(target.process) && HandleStillRunning(target.thread);
    }

    // 工作线程传入冻结目标及精确布局；返回同次采样并更新布局的完整运行身份匹配状态。
    LiveSample ReadLiveSample(const LiveTarget& target, Layout& layout)
    {
        LiveSample sample; // 尚无有效正文，不把旧 DynData 三元组当作完整运行身份。
        layout.runningMatch = false;
        if (!target.diagnostic.isEmpty())
        {
            sample.diagnostic = target.diagnostic;
            return sample;
        }
        if (!LiveTargetRunning(target))
        {
            sample.diagnostic = QStringLiteral("冻结的目标已退出或无法复核存活状态；未采用本次采样");
            return sample;
        }
        if (layout.profile.fields.empty())
        {
            sample.diagnostic = QStringLiteral("未找到精确符号布局；未执行对象体采样");
            return sample;
        }

        // 新请求在固定详情之前独立执行；旧 DynData 缺失不阻塞新协议的内置精确配置。
        sample.body = ksword::ark::DriverClient().queryStructureSample(layout.profile, target.request);
        if (!LiveTargetRunning(target))
        {
            sample.body.identityVerified = false;
            sample.diagnostic = QStringLiteral("冻结的目标已退出或无法复核存活状态；未采用本次采样");
        }
        else if (sample.body.unsupported)
        {
            sample.diagnostic = QStringLiteral("驱动不支持当前内核的精确对象体采样");
        }
        else if (!sample.body.io.ok)
        {
            sample.diagnostic = QStringLiteral("对象体设备查询失败");
        }
        else if (!sample.body.identityVerified)
        {
            sample.diagnostic = QStringLiteral("对象身份、运行内核完整 RSDS 或结构大小未通过核验");
        }
        layout.runningMatch = sample.body.io.ok && sample.body.identityVerified && sample.diagnostic.isEmpty();
        sample.body.identityVerified = layout.runningMatch;
        return sample;
    }

    // GUI 线程传入同次结果；返回经过翻译的来源、读取区间和严格覆盖说明，不发起设备请求。
    QString DescribeLiveSample(const LiveSample& sample)
    {
        if (!sample.body.identityVerified)
        {
            QStringList reasons; // 保留本地失败类别、驱动原始诊断和状态码，不能以固定字段成功覆盖。
            reasons.append(i18n::displayText(sample.diagnostic));
            if (!sample.body.io.message.empty())
            {
                reasons.append(QString::fromStdString(sample.body.io.message));
            }
            reasons.append(QStringLiteral("Win32 %1 / sampleStatus %2 / NTSTATUS 0x%3")
                .arg(sample.body.io.win32Error).arg(sample.body.response.sampleStatus)
                .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(sample.body.io.ntStatus)), 8, 16, QLatin1Char('0')));
            return i18n::displayText(QStringLiteral("对象体快照不可用：%1")).arg(reasons.join(QStringLiteral(" · ")));
        }

        const auto& packet = sample.body.response; // 采样起止时间和对象地址来自同一正文回执。
        const auto& rows = sample.body.projection; // 使用投影器的全部行计数，不能拿已支持标量作分母。
        const double coverage = rows.totalRows ? 100.0 * static_cast<double>(rows.coverageRows) /
            static_cast<double>(rows.totalRows) : 0.0; // 严格覆盖率排除联合体和重复存储别名。
        QStringList parts; // 状态标签保留完整来源和覆盖口径，允许沿用既有自动换行。
        parts.append(i18n::displayText(QStringLiteral("对象体快照：%1 → %2（UTC）；非原子采样"))
            .arg(SampleTime(packet.sampleStartTime100ns), SampleTime(packet.sampleEndTime100ns)));
        parts.append(i18n::displayText(QStringLiteral("全部符号行 %1；已解码行 %2；联合体原始解释行 %3；严格覆盖 %4 / %1（%5%）"))
            .arg(static_cast<qulonglong>(rows.totalRows)).arg(static_cast<qulonglong>(rows.sampledRows))
            .arg(static_cast<qulonglong>(rows.unionRows)).arg(static_cast<qulonglong>(rows.coverageRows))
            .arg(coverage, 0, 'f', 1));
        parts.append(i18n::displayText(QStringLiteral("覆盖率分母包含全部符号行；严格覆盖分子排除联合体解释和重复存储别名")));
        return parts.join(QStringLiteral(" · "));
    }
}
