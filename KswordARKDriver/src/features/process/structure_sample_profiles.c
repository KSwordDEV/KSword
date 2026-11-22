// 为三个明确授权的内核生成精确配对事实，绝不推断相邻版本布局。
#include "structure_sample_profiles.h" // 引入私有不可变描述，请求不能替换此表。

// 输入为 PE/RSDS 记录，以及 profiles/{process,thread}_layouts 内精确根类型 TSV 的文件头。
// 下列 PE SHA256 仅是离线文件配对的来源证据，不声称它是已重定位内核内存的哈希。
// 每个根大小都来自精确 PDB 的 sizeof(_EPROCESS) 或 sizeof(_ETHREAD)，绝不是池分配费用。
static const KSW_STRUCTURE_SAMPLE_PROFILE KswStructureSampleProfiles[] = // 只授权三个内核身份及其各自两种根类型。
{ // 允许列表固定编译到驱动中，不接受运行时上传或修改。
    { // 配置一：宿主 NT 10.0.19041.7844，精确 RSDS 为 E2672D6A639304ECAF7D417B71DC4D0B1。
        { // 离线 PE SHA256：0f31902fd772b802bbda4292460e533ad19dce2cbb105f7771c76f0378ed4f1a。
            34404UL, // PE 架构为 AMD64。
            329465876UL, // 精确 PE 时间戳。
            17059840UL, // 精确 PE 加载映像大小。
            10925765UL, // 精确 PE 校验和。
            { // 按 Windows 原始字节顺序保存 GUID。
                0x6A, // GUID 第零字节。
                0x2D, // GUID 第一字节。
                0x67, // GUID 第二字节。
                0xE2, // GUID 第三字节。
                0x93, // GUID 第四字节。
                0x63, // GUID 第五字节。
                0xEC, // GUID 第六字节。
                0x04, // GUID 第七字节。
                0xAF, // GUID 第八字节。
                0x7D, // GUID 第九字节。
                0x41, // GUID 第十字节。
                0x7B, // GUID 第十一字节。
                0x71, // GUID 第十二字节。
                0xDC, // GUID 第十三字节。
                0x4D, // GUID 第十四字节。
                0x0B // GUID 第十五字节。
            }, // 此 GUID 不采用文本中的字节显示顺序。
            1UL, // 精确 RSDS Age，不是 PDB 摘要 Age。
            0UL // 第一版保留字段始终为零。
        }, // 两个 TSV 来源的文件名均为 34404-329465876-17059840.tsv。
        1UL, // 稳定且非零的配置标识。
        2624UL, // 精确 EPROCESS 根正文大小。
        2200UL // 精确 ETHREAD 根正文大小。
    }, // 进程 TSV SHA256：2fcf106e18a8ab7910f449f946d25a884fa797e2cca14c938d21240dddc88709。
    // 线程 TSV SHA256：2483154c30ddbefe7b727b36c042d2c205dfd5a0e2ee7407d38ef67a35e047a1。
    { // 配置二：Win10 来宾 NT 10.0.19041.631，精确 RSDS 为 F923DA2D238E7C7CE180B962B19A37811。
        { // 离线 PE SHA256：ce707a4009b1d65b8d3f51e572fee8939150afb8fde557d0e5ba66db90f1e4ac。
            34404UL, // PE 架构为 AMD64。
            3986539294UL, // 此精确文件与 PDB 配对的 PE 时间戳。
            17063936UL, // 此精确文件与 PDB 配对的加载映像大小。
            10875581UL, // 此精确文件与 PDB 配对的 PE 校验和。
            { // 按 Windows 原始字节顺序保存 GUID。
                0x2D, // GUID 第零字节。
                0xDA, // GUID 第一字节。
                0x23, // GUID 第二字节。
                0xF9, // GUID 第三字节。
                0x8E, // GUID 第四字节。
                0x23, // GUID 第五字节。
                0x7C, // GUID 第六字节。
                0x7C, // GUID 第七字节。
                0xE1, // GUID 第八字节。
                0x80, // GUID 第九字节。
                0xB9, // GUID 第十字节。
                0x62, // GUID 第十一字节。
                0xB1, // GUID 第十二字节。
                0x9A, // GUID 第十三字节。
                0x37, // GUID 第十四字节。
                0x81 // GUID 第十五字节。
            }, // 此 GUID 不借用宿主或其他修订版的身份。
            1UL, // 精确 RSDS Age。
            0UL // 第一版保留字段始终为零。
        }, // 两个 TSV 来源的文件名均为 34404-3986539294-17063936.tsv。
        2UL, // 稳定且非零的配置标识。
        2624UL, // 独立指定此内核的 EPROCESS 精确根大小。
        2200UL // 独立指定此内核的 ETHREAD 精确根大小。
    }, // 进程 TSV SHA256：a55b647ceb4923cbeef93d9daa23719f1b9178093e06c52403270703d739ff73。
    // 线程 TSV SHA256：65aac2793f7a030580d5b1e49f2b100e895c863b99144ad71e8f6203f3890a71。
    { // 配置三：Win11 来宾 NT 10.0.26100.9711，精确 RSDS 为 B661C6FE72991D160FE37C48B8BC54701。
        { // 离线 PE SHA256：4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a。
            34404UL, // PE 架构为 AMD64。
            2952155935UL, // 精确匹配 PE 时间戳，不使用系统营销版本号。
            21299200UL, // 此精确 PE 的加载映像大小。
            13151644UL, // 此精确 PE 的校验和。
            { // 按 Windows 原始字节顺序保存 GUID。
                0xFE, // GUID 第零字节。
                0xC6, // GUID 第一字节。
                0x61, // GUID 第二字节。
                0xB6, // GUID 第三字节。
                0x99, // GUID 第四字节。
                0x72, // GUID 第五字节。
                0x16, // GUID 第六字节。
                0x1D, // GUID 第七字节。
                0x0F, // GUID 第八字节。
                0xE3, // GUID 第九字节。
                0x7C, // GUID 第十字节。
                0x48, // GUID 第十一字节。
                0xB8, // GUID 第十二字节。
                0xBC, // GUID 第十三字节。
                0x54, // GUID 第十四字节。
                0x70 // GUID 第十五字节。
            }, // 此 GUID 必须与运行中内核完整匹配。
            1UL, // 精确 RSDS Age。
            0UL // 第一版保留字段始终为零。
        }, // 两个 TSV 来源的文件名均为 34404-2952155935-21299200.tsv。
        3UL, // 稳定且非零的配置标识。
        2112UL, // Win11 EPROCESS 不能借用更大的 Win10 根范围。
        1944UL // Win11 ETHREAD 不能借用更大的 Win10 根范围。
    } // 进程 TSV SHA256：472dcc419e989fad55ad48444d9fb172954bb12bfa2256de7baaa4c097d72276。
    // 线程 TSV SHA256：756a66a8afe3efe85a1a87885122c2caa6d2be25a1351f53c43cb4af37751e3e。
}; // 此表不支持动态更新、调用方上传或相邻版本回退。

// 功能：逐字段匹配已校验身份；输入为解析器身份，输出为借用的只读配置或空指针。
const KSW_STRUCTURE_SAMPLE_PROFILE* // 查找本身不读取任何对象正文。
KswStructureSampleFindProfile( // 输入不是直接来自 IOCTL 的布局元数据。
    const KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID* Kernel // 解析器已经验证的运行内核身份。
    ) // 不转移输入身份或输出配置的所有权。
{ // 采用显式字段比较，不依赖结构填充字节。
    ULONG index; // 最多检查三个编译内置配置。
    if (Kernel == NULL || Kernel->reserved != 0UL) // 内部参数无效时不猜测身份。
    { // 没有完整合法身份就没有可授权的根范围。
        return NULL; // 明确表示配置不可用。
    } // 身份准入仍需核对全部 PE 与 CodeView 字段。
    for (index = 0UL; index < RTL_NUMBER_OF(KswStructureSampleProfiles); ++index) // 遍历固定且有界的配置表。
    { // 每个候选均为不可变的编译数据。
        const KSW_STRUCTURE_SAMPLE_PROFILE* profile = &KswStructureSampleProfiles[index]; // 当前待核对配置。
        if (Kernel->machine == profile->Kernel.machine && // 精确比较映像架构。
            Kernel->timeDateStamp == profile->Kernel.timeDateStamp && // 精确比较 COFF 时间戳。
            Kernel->sizeOfImage == profile->Kernel.sizeOfImage && // 精确比较加载映像大小。
            Kernel->checkSum == profile->Kernel.checkSum && // 精确比较 PE 校验和。
            Kernel->pdbAge == profile->Kernel.pdbAge && // Age 与 GUID 身份分别比较。
            RtlCompareMemory( // 比较全部十六个原始 GUID 字节。
                Kernel->pdbGuid, // 运行中内核的实际 GUID。
                profile->Kernel.pdbGuid, // 编译配置的精确 GUID。
                sizeof(Kernel->pdbGuid)) == sizeof(Kernel->pdbGuid)) // 必须全部字节一致，不能接受前缀匹配。
        { // 精确匹配身份后仍需验证配置范围。
            if (profile->ProfileId == 0UL || // 不完整配置不能获得稳定标识。
                profile->EprocessSize == 0UL || // 进程根大小必须有效。
                profile->EthreadSize == 0UL || // 线程根大小必须有效。
                profile->EprocessSize > KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES || // 输出容量只是额外的硬性上限。
                profile->EthreadSize > KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES) // 两种对象自身的范围必须分别合法。
            { // 错误生成的配置不能授权更宽的读取范围。
                return NULL; // 配置事实异常时明确失败关闭。
            } // 精确身份不能绕过对象范围验证。
            return profile; // 仅此匹配项能够定义两种对象的授权根大小。
        } // 身份不符时绝不复用当前候选的根大小。
    } // 每个允许的精确配置均只检查一次。
    return NULL; // 未知内核或类型组合明确不支持。
} // 不保留全局状态、对象引用或调用方控制的布局。
