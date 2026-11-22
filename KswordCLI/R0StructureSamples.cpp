#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace ks::cli
{
    namespace
    {
        namespace layout = ks::threadlayout; // 精确磁盘 PE 与符号布局的共享入口。
        namespace sample = ks::structure_sample; // 共享位图投影，不在 CLI 重新解码对象。
        namespace fs = std::filesystem; // 仅处理磁盘配置与系统内核路径。
        using ksword::ark::StructureSampleResult;

        // 功能：将 UTF-8 元数据转为 CLI Unicode；输入原文，输出文字，非法编码返回空串。
        std::wstring Wide(const std::string& text)
        {
            if (text.empty() || text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return {};
            }
            const auto bytes = static_cast<int>(text.size()); // Windows 转码接口要求的有界字节数。
            const auto length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                text.data(), bytes, nullptr, 0); // 严格计算 UTF-16 容量，不替换损坏字符。
            if (!length)
            {
                return {};
            }
            std::wstring output(static_cast<std::size_t>(length), L'\0'); // 当前字符串的完整转换结果。
            if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                text.data(), bytes, output.data(), length) != length)
            {
                return {};
            }
            return output;
        }

        // 功能：定位本机系统内核；无输入，输出磁盘路径，系统目录查询失败时返回空路径。
        fs::path SystemKernelPath()
        {
            std::wstring system(32768, L'\0'); // 系统目录的 Unicode 路径缓冲。
            const auto length = ::GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size())); // 返回的目录字符数。
            if (!length || length >= system.size())
            {
                return {};
            }
            system.resize(length);
            return fs::path(system) / L"ntoskrnl.exe";
        }

        // 功能：定位默认配置根目录；无输入，输出 CLI 同目录 profiles，不搜索邻版配置。
        fs::path DefaultProfiles()
        {
            std::wstring image(32768, L'\0'); // 当前可执行文件的完整 Unicode 路径。
            const auto length = ::GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size())); // 返回的映像路径字符数。
            if (!length || length >= image.size())
            {
                return {};
            }
            image.resize(length);
            return fs::path(image).parent_path() / L"profiles";
        }

        // 功能：序列化可选磁盘路径；输入路径，输出 JSON 字符串，未知路径输出 null。
        Json PathJson(const fs::path& path)
        {
            return path.empty() ? Json{} : Json::string(path.wstring());
        }

        // 功能：格式化驱动回执的 RSDS；输入原始 GUID/Age，输出与分片相同的完整符号键。
        std::wstring KernelPdbKey(const KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID& kernel)
        {
            GUID guid{}; // Windows 内存字节顺序的 GUID，仅用于格式化，不解释为地址。
            std::memcpy(&guid, kernel.pdbGuid, sizeof(guid));
            std::wostringstream output; // 逐部分保留 GUID 的固定宽度及十六进制 Age。
            output << std::hex << std::uppercase << std::setfill(L'0')
                << std::setw(8) << guid.Data1 << std::setw(4) << guid.Data2 << std::setw(4) << guid.Data3;
            for (const auto byte : guid.Data4) // 尾部八字节按 GUID 标准文本顺序输出。
            {
                output << std::setw(2) << static_cast<unsigned int>(byte);
            }
            output << kernel.pdbAge;
            return output.str();
        }

        // 功能：输出磁盘 PE/RSDS；输入共享身份，输出完整身份或 null，不代表加载中身份。
        Json DiskIdentity(const layout::Identity& identity)
        {
            if (identity.machine != IMAGE_FILE_MACHINE_AMD64 || !identity.imageSize || identity.pdbKey.empty())
            {
                return {};
            }
            return Json::object({
                {L"machine", Json::number(identity.machine)},
                {L"timestamp", Json::number(identity.timestamp)},
                {L"imageSize", Json::number(identity.imageSize)},
                {L"pdbKey", Json::string(Wide(identity.pdbKey))}
            });
        }

        // 功能：输出真实回执内核元数据；输入已校验格式的回执，输出加载中 PE/完整 RSDS。
        Json LoadedIdentity(const KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE& response)
        {
            if ((response.flags & KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID_VALID) == 0)
            {
                return {};
            }
            const auto& kernel = response.kernel; // 本次驱动回执的实际加载内核，不使用磁盘缓存替代。
            return Json::object({
                {L"machine", Json::number(kernel.machine)},
                {L"timestamp", Json::number(kernel.timeDateStamp)},
                {L"imageSize", Json::number(kernel.sizeOfImage)},
                {L"checkSum", Json::number(kernel.checkSum)},
                {L"pdbKey", Json::string(KernelPdbKey(kernel))},
                {L"pdbAge", Json::number(kernel.pdbAge)}
            });
        }

        // 功能：冻结 R3 可访问对象；构造时比较可选期望时间，句柄一直持有到本次采样结束。
        struct TargetLease
        {
            process::Lease process; // 已核对 PID/创建时间的进程句柄及查询结果。
            ks::r3::common::UniqueHandle thread; // ETHREAD 采样期间持有同一线程实例。
            DWORD tid = 0; // 冻结的目标线程 ID，进程采样时为零。
            DWORD owner = 0; // 由持有线程句柄取得的实际进程 ID。
            DWORD error = ERROR_SUCCESS; // 线程身份查询失败的 Win32 原因。
            std::uint64_t threadCreation = 0; // 由线程句柄取得的真实 FILETIME。
            bool threadMatched = false; // 可选期望时间和进程归属均一致时成立。

            // 调用：传入已校验命令参数及根类型；输出由本对象保存的身份、句柄和错误。
            TargetLease(const Args& args, const layout::Kind kind) :
                process(args), tid(kind == layout::Kind::Thread ? args.u32(L"--tid") : 0)
            {
                if (kind != layout::Kind::Thread || !process.matches || !process.creationTime || !process.alive())
                {
                    return;
                }
                thread.reset(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
                if (!thread.valid())
                {
                    error = ::GetLastError();
                    return;
                }
                owner = ::GetProcessIdOfThread(thread.get());
                if (!owner)
                {
                    error = ::GetLastError();
                    return;
                }
                FILETIME created{}, exited{}, kernel{}, user{}; // 只使用创建时间，其他值供 Windows API 接收。
                if (!::GetThreadTimes(thread.get(), &created, &exited, &kernel, &user))
                {
                    error = ::GetLastError();
                    return;
                }
                threadCreation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32U) | created.dwLowDateTime;
                threadMatched = threadCreation && owner == process.pid &&
                    (!args.has(L"--thread-creation-time") || threadCreation == args.integer(L"--thread-creation-time"));
            }

            // 功能：下发前检查同一对象仍存活；输入根类型，输出是否允许采样，不凭退出码 259 判断。
            bool ready(const layout::Kind kind) const
            {
                return process.matches && process.creationTime && process.alive() &&
                    (kind == layout::Kind::Process || (threadMatched && thread.valid() &&
                        ::WaitForSingleObject(thread.get(), 0) == WAIT_TIMEOUT));
            }

            // 功能：保留句柄身份查询结果；输入根类型，输出用于诊断的进程、线程及存活状态。
            Json json(const layout::Kind kind) const
            {
                return Json::object({
                    {L"process", process.json()},
                    {L"tid", kind == layout::Kind::Thread ? Json::number(tid) : Json{}},
                    {L"ownerPid", owner ? Json::number(owner) : Json{}},
                    {L"threadCreationTime100ns", threadCreation ? Json::count(threadCreation) : Json{}},
                    {L"threadIdentityMatched", kind == layout::Kind::Thread ? Json::boolean(threadMatched) : Json{}},
                    {L"aliveAtReadback", Json::boolean(ready(kind))},
                    {L"threadWin32Error", Json::number(error)}
                });
            }
        };

        // 功能：保存单次命令归属；参数解析、磁盘布局和驱动回执不会写入其他命令的缓存。
        struct SampleContext
        {
            layout::Kind kind = layout::Kind::Process; // 当前根类型，决定配置子目录和身份要求。
            fs::path kernel; // 本机系统目录内核路径，不能选择任意离线内核。
            fs::path profiles; // 调用者指定或可执行文件旁的配置根目录。
            fs::path shard; // 由磁盘 PE 三元组定位、再由完整 RSDS 校验的唯一分片。
            layout::Identity disk; // 磁盘身份只用于选择精确布局，不代替已加载内核验证。
            layout::Profile profile; // 全量符号行；覆盖率分母始终包括未采样行。
            KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST request{}; // 只含根类型与冻结身份，没有偏移或地址。
            Json target; // 持有句柄的实际身份与读取后存活状态。
            bool targetAlive = false; // 下发前及回读时均需确认同一目标仍存活，否则不发布字段。
        };

        // 功能：决定是否允许公开字段；输入本次上下文/共享结果，输出完整身份与逐行对齐的判定。
        bool CanPublish(const SampleContext& context, const StructureSampleResult& result)
        {
            return context.targetAlive && result.io.ok && result.identityVerified && result.projection.identityMatched &&
                result.projection.totalRows == context.profile.fields.size() &&
                result.projection.fields.size() == context.profile.fields.size();
        }

        // 功能：序列化一个共享投影行；输入符号元数据/投影/行号，输出零值与缺失值明确区分的 JSON。
        Json FieldJson(const layout::Field& source, const sample::FieldValue& field, const std::uint32_t id,
            const std::uint64_t objectAddress)
        {
            const bool sampled = field.status == sample::FieldStatus::Sampled; // 只有位图覆盖完整标量才公开数值。
            const bool located = field.status != sample::FieldStatus::InvalidLayout &&
                objectAddress <= (std::numeric_limits<std::uint64_t>::max)() - field.offset; // 展示地址也拒绝溢出。
            return Json::object({
                {L"id", Json::number(id)},
                {L"parent", Json::number(source.parent)},
                {L"name", Json::string(Wide(source.name))},
                {L"type", Json::string(Wide(source.type))},
                {L"path", Json::string(Wide(field.path))},
                {L"status", Json::string(Wide(sample::StatusName(field.status)))},
                {L"sampled", Json::boolean(sampled)},
                // 偏移相对于根对象；原始父相对偏移另列保留，位域仍沿用精确符号定义。
                {L"offset", Json::number(field.offset)},
                {L"parentRelativeOffset", Json::number(source.offset)},
                {L"storageAddress", located ? Json::hex(objectAddress + field.offset) : Json{}},
                {L"width", Json::number(field.width)},
                {L"bitOffset", source.bitOffset < 0 ? Json{} : Json::signedNumber(source.bitOffset)},
                {L"bitWidth", source.bitWidth < 0 ? Json{} : Json::signedNumber(source.bitWidth)},
                {L"raw", sampled ? Json::hex(field.raw) : Json{}},
                {L"value", sampled ? Json::hex(field.value) : Json{}},
                {L"valueBits", sampled ? Json::number(field.valueBits) : Json{}},
                {L"text", sampled ? Json::string(Wide(field.text)) : Json{}},
                // 联合体只报告共同存储解释，不能据此声明活动分支或增加严格覆盖数。
                {L"unionInterpretation", Json::boolean(field.unionInterpretation)},
                {L"activeUnionBranchKnown", Json::boolean(false)}
            });
        }

        // 功能：给回执状态提供稳定名称；输入协议状态，输出名称，不把未知状态当成成功。
        const wchar_t* SampleStatusName(const unsigned long status)
        {
            switch (status)
            {
            case KSWORD_ARK_STRUCTURE_SAMPLE_OK:
                return L"ok";
            case KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL:
                return L"partial";
            case KSWORD_ARK_STRUCTURE_SAMPLE_INVALID_REQUEST:
                return L"invalid_request";
            case KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED:
                return L"kernel_unsupported";
            case KSWORD_ARK_STRUCTURE_SAMPLE_LOOKUP_FAILED:
                return L"lookup_failed";
            case KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH:
                return L"identity_mismatch";
            case KSWORD_ARK_STRUCTURE_SAMPLE_READ_FAILED:
                return L"read_failed";
            }
            return L"unknown";
        }

        // 功能：整理本次命令 JSON；输入上下文/可选真实回执/可用性，输出同一来源的完整结果。
        Json SampleJson(const SampleContext& context, const StructureSampleResult* result,
            const wchar_t* availability)
        {
            const bool receipt = result && result->io.ok; // 只有共享客户端接受的完整协议头才作为有效回执。
            const bool verified = result && CanPublish(context, *result); // 身份失败时字段及采样计数均不公开。
            const auto* packet = receipt ? &result->response : nullptr; // 固定 0x941 回执，不用其他查询拼装数据。
            const auto* projection = verified ? &result->projection : nullptr; // 全量行与有效位图属于同次采样。
            std::vector<Json> fields; // 与原始 profile.fields 一一对应，包括聚合和不可读行。
            Json validBitmap; // 仅公开已验证根范围的真实逐字节有效位，不附带合成零缓冲。
            if (verified)
            {
                fields.reserve(projection->fields.size());
                for (std::size_t index = 0; index < projection->fields.size(); ++index) // 当前符号行的一基序号。
                {
                    fields.push_back(FieldJson(context.profile.fields[index], projection->fields[index],
                        static_cast<std::uint32_t>(index + 1), packet->objectAddress));
                }
                const auto size = static_cast<std::size_t>((packet->rootSize + 7UL) / 8UL); // 根内位图的实际字节数。
                const std::vector<std::uint8_t> bitmap(packet->valid, packet->valid + size); // 从驱动回执直接复制。
                validBitmap = Json::bytes(bitmap, bitmap.size());
            }

            // 覆盖率验收分子由共享投影去重并排除 union，分母包括每一条符号行。
            const bool majority = verified && projection->coverageRows * 2 > projection->totalRows;
            const auto count = [verified](const std::size_t value) // 将有界行数作为 JSON 数字，身份未知时保持 null。
            {
                return verified ? Json::number(static_cast<std::uint32_t>(value)) : Json{};
            };
            return Json::object({
                {L"availability", Json::string(availability)},
                {L"source", Json::string(L"live_object_body")},
                {L"live", Json::boolean(true)},
                {L"atomic", Json::boolean(false)},
                {L"metadataOnly", Json::boolean(false)},
                {L"sampleAvailable", Json::boolean(verified && projection->sampledRows != 0)},
                {L"identityVerified", Json::boolean(verified)},
                {L"driverIdentityVerified", Json::boolean(result && result->identityVerified)},
                // 所有期望时间都在持有目标句柄后冻结，再交给驱动对实际引用对象独立核验。
                {L"pid", Json::number(context.request.processId)},
                {L"tid", context.kind == layout::Kind::Thread ? Json::number(context.request.threadId) : Json{}},
                {L"expectedProcessCreationTime100ns", context.request.processCreationTime100ns ?
                    Json::count(context.request.processCreationTime100ns) : Json{}},
                {L"expectedThreadCreationTime100ns", context.request.threadCreationTime100ns ?
                    Json::count(context.request.threadCreationTime100ns) : Json{}},
                {L"target", context.target},
                {L"objectAddress", verified ? Json::hex(packet->objectAddress) : Json{}},
                {L"processCreationTime100ns", verified ? Json::count(packet->processCreationTime100ns) : Json{}},
                {L"threadCreationTime100ns", verified && context.kind == layout::Kind::Thread ?
                    Json::count(packet->threadCreationTime100ns) : Json{}},
                // 磁盘身份、加载中身份和配置来源分别报告，不把磁盘匹配当作现场校验。
                {L"rootType", Json::string(context.kind == layout::Kind::Thread ? L"_ETHREAD" : L"_EPROCESS")},
                {L"kernelPath", PathJson(context.kernel)},
                {L"diskKernelIdentity", DiskIdentity(context.disk)},
                {L"loadedKernelIdentity", receipt ? LoadedIdentity(*packet) : Json{}},
                {L"profilesRoot", PathJson(context.profiles)},
                {L"profilePath", PathJson(context.shard)},
                {L"profileRootSize", context.profile.rootSize ? Json::number(context.profile.rootSize) : Json{}},
                {L"profileId", packet && packet->profileId ? Json::number(packet->profileId) : Json{}},
                // 时间为 Windows UTC FILETIME（100ns）；字符串避免 JSON 消费者丢失 64 位精度。
                {L"sampleStartTime100ns", packet && packet->sampleStartTime100ns ?
                    Json::count(packet->sampleStartTime100ns) : Json{}},
                {L"sampleEndTime100ns", packet && packet->sampleEndTime100ns ?
                    Json::count(packet->sampleEndTime100ns) : Json{}},
                {L"sampleStatus", packet ? Json::string(SampleStatusName(packet->sampleStatus)) : Json{}},
                {L"sampleStatusCode", packet ? Json::number(packet->sampleStatus) : Json{}},
                {L"rootSize", packet ? Json::number(packet->rootSize) : Json{}},
                {L"bytesCopied", packet ? Json::number(packet->bytesCopied) : Json{}},
                {L"validByteBitmap", validBitmap},
                {L"flags", packet ? Json::hex(packet->flags) : Json{}},
                // 返回全部行数，同时把成功标量、union 解释和严格覆盖分子分开，不能互相替代。
                {L"totalRows", Json::number(static_cast<std::uint32_t>(context.profile.fields.size()))},
                {L"sampledRows", count(projection ? projection->sampledRows : 0)},
                {L"unionRows", count(projection ? projection->unionRows : 0)},
                {L"coverageRows", count(projection ? projection->coverageRows : 0)},
                {L"aggregateRows", count(projection ? projection->aggregateRows : 0)},
                {L"unsupportedRows", count(projection ? projection->unsupportedRows : 0)},
                {L"unreadRows", count(projection ? projection->unreadRows : 0)},
                {L"coverageExceedsHalf", Json::boolean(majority)},
                // 传输结果与采样覆盖率独立；没有打开设备不能描述为已经发出了 IOCTL。
                {L"ioctlFunction", Json::hex(KSWORD_ARK_IOCTL_FUNCTION_QUERY_STRUCTURE_SAMPLE)},
                {L"deviceAccessAttempted", Json::boolean(result != nullptr)},
                {L"requestAttempted", Json::boolean(result && !result->io.deviceOpenFailed)},
                {L"deviceOpenFailed", Json::boolean(result && result->io.deviceOpenFailed)},
                {L"win32Error", result ? Json::number(result->io.win32Error) : Json{}},
                {L"ntStatus", packet ? Json::hex(static_cast<std::uint32_t>(packet->lastStatus)) : Json{}},
                {L"coverageRule", Json::string(L"coverageRows * 2 > totalRows; unique non-union sampled storage only; all profile rows in denominator")},
                {L"limitations", Json::strings({
                    L"Non-atomic read interval: fields can change independently while the root object is copied.",
                    L"Union rows are raw storage interpretations, not identified active branches, and never count toward coverageRows.",
                    L"Pointer values are numbers only; no object header, adjacent allocation, or pointee is read.",
                    L"A sampled zero is 0x0 with sampled=true; missing values are null with an explicit field status."
                })},
                {L"fields", Json::array(fields)}
            });
        }

        // 功能：保持 CLI 的传输退出码语义；输入共享失败结果，输出设备/格式/不支持/传输错误码。
        int IoFailure(const StructureSampleResult& result)
        {
            if (result.io.deviceOpenFailed)
            {
                return 2;
            }
            if (result.io.win32Error == ERROR_INVALID_DATA)
            {
                return 4;
            }
            if (result.unsupported || result.io.win32Error == ERROR_INVALID_FUNCTION ||
                result.io.win32Error == ERROR_NOT_SUPPORTED || result.io.win32Error == ERROR_CALL_NOT_IMPLEMENTED ||
                result.io.win32Error == ERROR_PROC_NOT_FOUND)
            {
                return 5;
            }
            return 3;
        }

        // 功能：执行一次只读现场采样；输入 CLI 参数及根类型，输出明确退出码、真实回执及全部符号行。
        Result RunSample(const Args& args, const layout::Kind kind)
        {
            SampleContext context; // 当前命令的参数、磁盘证据和字段归属，不跨请求保留。
            context.kind = kind;
            context.request.version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION;
            context.request.objectType = kind == layout::Kind::Thread ?
                KSWORD_ARK_STRUCTURE_SAMPLE_ETHREAD : KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS;
            (void)args.require(L"--pid");
            context.request.processId = args.u32(L"--pid");
            if (!context.request.processId || args.get(L"--backend", L"r0") != L"r0")
            {
                throw std::invalid_argument("positive --pid and --backend r0 required");
            }

            // 线程采样必须明确指定 TID；进程命令的帮助元数据不接受线程专用选项。
            if (kind == layout::Kind::Thread)
            {
                (void)args.require(L"--tid");
                context.request.threadId = args.u32(L"--tid");
                if (!context.request.threadId)
                {
                    throw std::invalid_argument("--tid must be positive");
                }
            }
            context.request.processCreationTime100ns = args.integer(L"--creation-time");
            context.request.threadCreationTime100ns = args.integer(L"--thread-creation-time");
            if ((args.has(L"--creation-time") && !context.request.processCreationTime100ns) ||
                (args.has(L"--thread-creation-time") && !context.request.threadCreationTime100ns))
            {
                throw std::invalid_argument("creation times must be positive FILETIME values");
            }
            if ((args.has(L"--profiles") && args.get(L"--profiles").empty()) ||
                (args.has(L"--kernel") && args.get(L"--kernel").empty()))
            {
                throw std::invalid_argument("--profiles and --kernel must not be empty");
            }

            // 调用：用于尚未访问设备的失败路径；输入退出码/稳定状态/诊断，输出不含字段的结果。
            const auto preflightFailure = [&context](const int code, const wchar_t* availability,
                const wchar_t* diagnostic)
            {
                return Result{code, SampleJson(context, nullptr, availability), {diagnostic}};
            };
            context.kernel = SystemKernelPath();
            context.profiles = args.has(L"--profiles") ? fs::path(args.get(L"--profiles")) : DefaultProfiles();
            if (context.kernel.empty())
            {
                return preflightFailure(5, L"system_kernel_unavailable", L"Could not locate the system disk kernel.");
            }

            // --kernel 只是显式确认系统文件，绝不允许用任意磁盘 PE 为现场正文选择布局。
            if (args.has(L"--kernel"))
            {
                std::error_code error; // 路径、权限或文件身份查询错误均不能放行任意镜像。
                if (!fs::equivalent(fs::path(args.get(L"--kernel")), context.kernel, error) || error)
                {
                    throw std::invalid_argument("--kernel must identify the system ntoskrnl.exe; arbitrary live kernel images are forbidden");
                }
            }
            context.disk = layout::ReadImageIdentity(context.kernel);
            if (context.disk.machine != IMAGE_FILE_MACHINE_AMD64 || !context.disk.imageSize || context.disk.pdbKey.empty())
            {
                return preflightFailure(5, L"disk_identity_unavailable",
                    L"Could not read the AMD64 system disk kernel's complete PE/RSDS identity.");
            }
            if (context.profiles.empty())
            {
                return preflightFailure(5, L"profile_directory_unavailable",
                    L"Could not locate the profiles root beside the CLI executable; use --profiles DIR.");
            }

            // PE 三元组只定位候选分片；Load 继续精确核对根类型与完整 GUID/Age，不搜索最近版本。
            context.shard = context.profiles / layout::Directory(kind) / layout::FileName(context.disk);
            context.profile = layout::Load(context.shard, &context.disk, kind);
            if (context.profile.fields.empty() || context.profile.rootSize > KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES)
            {
                return preflightFailure(5, L"profile_unavailable",
                    L"The exact disk PE/RSDS layout is missing, invalid, mismatched, or exceeds the bounded sampling capacity.");
            }
            for (const auto& field : context.profile.fields) // 每条符号行必须能够无损显示，不静默替换损坏编码。
            {
                if (Wide(field.name).empty() || Wide(field.type).empty())
                {
                    return preflightFailure(5, L"profile_unavailable", L"The exact layout contains invalid UTF-8 field text.");
                }
            }

            // 持有原进程/线程句柄，比较可选期望时间；未提供时间时从句柄冻结真实值。
            const TargetLease target(args, kind); // 作用域覆盖整个同步 IOCTL 和 JSON 回读。
            context.target = target.json(kind);
            context.targetAlive = target.ready(kind);
            if (!context.targetAlive)
            {
                return preflightFailure(3, L"target_identity_unavailable",
                    L"The held target is inaccessible, exited, has a mismatched creation time, or belongs to another process; no R0 request was sent.");
            }
            context.request.processCreationTime100ns = target.process.creationTime;
            context.request.threadCreationTime100ns = kind == layout::Kind::Thread ? target.threadCreation : 0;

            // 唯一采样路径：共享客户端发送真实 0x941，并按实际回执位图投影；不构造测试快照。
            const auto result = ksword::ark::DriverClient().queryStructureSample(context.profile, context.request);
            context.target = target.json(kind);
            context.targetAlive = target.ready(kind);
            std::vector<std::wstring> diagnostics; // 只保存本次共享客户端消息和明确的失败/覆盖率说明。
            if (!result.io.message.empty())
            {
                diagnostics.push_back(Wide(result.io.message));
            }
            if (!result.io.ok)
            {
                return {IoFailure(result), SampleJson(context, &result, L"transport_or_protocol_failed"),
                    std::move(diagnostics)};
            }
            if (!context.targetAlive)
            {
                diagnostics.push_back(L"The held target exited during the query; no object fields are published.");
                return {3, SampleJson(context, &result, L"target_exited"), std::move(diagnostics)};
            }

            // 有效拒绝回执与错误协议分开；身份未确认时 SampleJson 始终输出 fields=[]。
            if (!CanPublish(context, result))
            {
                int code = 5; // 精确布局或内核证据不可用，默认不能宣称成功。
                const wchar_t* availability = L"kernel_identity_or_layout_mismatch"; // 稳定的机器可读拒绝原因。
                if (result.response.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_IDENTITY_MISMATCH ||
                    result.response.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_LOOKUP_FAILED)
                {
                    code = 3;
                    availability = SampleStatusName(result.response.sampleStatus);
                }
                else if (result.unsupported || result.response.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED ||
                    result.response.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_READ_FAILED)
                {
                    availability = SampleStatusName(result.response.sampleStatus);
                }
                else if (result.identityVerified || (result.response.sampleStatus != KSWORD_ARK_STRUCTURE_SAMPLE_OK &&
                    result.response.sampleStatus != KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL))
                {
                    code = 4;
                    availability = L"invalid_response_or_projection";
                }
                diagnostics.push_back(L"No fields are published without the exact loaded kernel RSDS, root size, owner and creation identities.");
                return {code, SampleJson(context, &result, availability), std::move(diagnostics)};
            }

            // 严格超过一半才退出 0；部分位图或大量 union/父行都不能通过改分母升级为成功。
            const bool majority = result.projection.coverageRows * 2 > result.projection.totalRows;
            if (!majority)
            {
                diagnostics.push_back(L"Identity verified, but strict unique non-union coverage does not exceed half of all profile rows; exit 6 (partial).");
            }
            return {majority ? 0 : 6, SampleJson(context, &result,
                majority ? L"available" : L"coverage_not_above_half"), std::move(diagnostics)};
        }
    }

    // 功能：注册两个独立现场命令；无输入输出，仅添加 R0/help 元数据，不修改离线 query。
    void registerR0StructureSamples()
    {
        // 调用：传入命令路径和根类型；输出注册项，参数语法同时驱动内置帮助和未知选项检查。
        const auto add = [](const wchar_t* path, const layout::Kind kind)
        {
            const bool thread = kind == layout::Kind::Thread; // ETHREAD 额外要求 TID，可选比较线程创建时间。
            Command command; // 独立注册项，不覆盖既有布局 query 或其他后端。
            command.path = path;
            command.syntax = std::wstring(L"KswordCLI.exe ") + path + L" --pid PID" +
                (thread ? L" --tid TID" : L"") + L" [--creation-time FILETIME]" +
                (thread ? L" [--thread-creation-time FILETIME]" : L"") +
                L" [--profiles DIR] [--kernel PATH] [--backend r0] [--json]";
            command.summary = thread ? L"Sample the live ETHREAD body using the exact loaded kernel identity." :
                L"Sample the live EPROCESS body using the exact loaded kernel identity.";
            command.options = std::wstring(L"Required: --pid") + (thread ? L", --tid. " : L". ") +
                L"Optional: --creation-time positive Windows FILETIME, compared against the held process; otherwise frozen from it. " +
                (thread ? L"--thread-creation-time positive FILETIME, compared against the held thread; otherwise frozen from it. " : L"") +
                L"--profiles root DIR (default: profiles beside the CLI); --kernel PATH (only the system ntoskrnl.exe, also the default); --backend r0 only; --json.";
            // 用户必须能从帮助区分非原子字段、union 原始解释、真实位图和覆盖率验收退出码。
            command.notes = L"Read-only live_object_body, live=true, atomic=false. Requires held, alive query handles and matching thread ownership. "
                L"Loads an exact disk PE/RSDS profile, then the shared 0x941 client verifies the referenced object creation identities and actual loaded full RSDS. "
                L"No arbitrary --kernel, nearest-version profile, R3 sampling fallback, synthetic bytes or pointer dereference. "
                L"All profile rows are retained; only complete valid-bitmap scalar storage is decoded. Zero values are distinct from null/missing. "
                L"raw/value preserve hexadecimal bits; text includes signed or boolean interpretation. Union rows are raw interpretations, not active branches. "
                L"Exit 0 only when identity verified and coverageRows*2>totalRows; coverageRows excludes all union interpretations and duplicate storage, "
                L"while totalRows includes parents and unsupported fields. Verified coverage at or below half returns 6 (partial); "
                L"unavailable exact evidence returns 5; identity/liveness failure 3, malformed response 4, device-open failure 2, arguments 1. No fields on identity failure.";
            command.supportsR0 = true;
            command.supportsR3 = false;
            command.defaultBackend = L"r0";
            command.run = [kind](const Args& args) // 参数经登记语法校验后交由同一现场实现执行。
            {
                return RunSample(args, kind);
            };
            addCommand(std::move(command));
        };
        add(L"process layout sample", layout::Kind::Process);
        add(L"process thread layout sample", layout::Kind::Thread);
    }
}
