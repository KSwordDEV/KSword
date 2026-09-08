/*++

Module Name:

    hvm_inject.c

Abstract:

    R-1 层的进程注入。语义见 hvm_inject.h 与协议头。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_inject.h"
#include "hvm_ept.h"
#include "hvm_ept_view.h"
#include "hvm_memory.h"

#if defined(_M_AMD64)

/* CR3 低位带 PCID 与标志，比较前必须掩掉。 */
#define KSW_HVM_INJECT_CR3_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* 页对齐掩码。 */
#define KSW_HVM_INJECT_PAGE_MASK 0xFFFFFFFFFFFFF000ULL

/* 拒绝对 Idle 与 System 动手，理由同进程处置。 */
#define KSW_HVM_INJECT_PID_IDLE 0UL
#define KSW_HVM_INJECT_PID_SYSTEM 4UL

/*
 * 外壳的固定开销。
 *
 * 前后各一段保存/恢复，加上结尾的绝对跳转与八字节返回地址槽。DLL 类型还要额外
 * 的 lea/mov/call 与路径本身，那部分按需另算。
 */
#define KSW_HVM_INJECT_PROLOGUE_BYTES 35UL
#define KSW_HVM_INJECT_EPILOGUE_BYTES 32UL
/*
 * DLL 类型除路径压栈之外的固定部分：
 * mov rcx,rsp(3) + sub rsp,32(4) + mov rax,imm64(10) + call rax(2)。
 */
#define KSW_HVM_INJECT_CALL_BYTES 19UL
/* 路径每八个字节一组，每组 mov rax,imm64(10) + push rax(1)。 */
#define KSW_HVM_INJECT_PATH_CHUNK_BYTES 11UL

/* 一条注入的完整驱动侧状态。 */
typedef struct _KSW_HVM_INJECT_SLOT
{
    /* 非零表示本槽在用。 */
    BOOLEAN InUse;
    /*
     * 载荷是否已经跑过。
     *
     * 一次性是刻意的：被劫持的是一个正在跑的线程，每次它执行到这一页就再跑一遍
     * 载荷，等于把那个线程变成一个不受控的循环。要重复执行，重新下达一次。
     */
    BOOLEAN Fired;
    UCHAR Reserved0[2];
    /* 下达时的 PID，只用于回报。 */
    ULONG ProcessId;
    /* 载荷本体长度。 */
    ULONG PayloadBytes;
    /* 外壳在页内的偏移，也就是 RIP 会被指向的位置。 */
    ULONG CaveOffset;
    /* 外壳加载荷占掉的总长度。 */
    ULONG CaveBytes;
    /* 结尾那条 jmp rel32 的操作数在页内的偏移，违规时把返回位移回填到这里。 */
    ULONG ReturnSlotOffset;
    /* 本条占用的执行视图标识。 */
    ULONG ViewId;
    /* 目标地址空间，已掩成层次物理页帧。 */
    ULONGLONG DirectoryBase;
    /* 被劫持那一页的客户物理地址，页对齐。 */
    ULONGLONG GuestPhysicalAddress;
    /* 被劫持那一页的客户线性地址，页对齐。RIP 由它加偏移算出。 */
    ULONGLONG GuestLinearAddress;
    /* 载荷被执行的次数。一次性注入完成后应为 1。 */
    volatile LONG64 ExecutionCount;
} KSW_HVM_INJECT_SLOT;

/*
 * 这张表放在模块静态存储里，不放进 KSW_HVM_RUNTIME。
 *
 * 运行时结构已经很大，而这张表只有四条、且只被本模块和退出路径上的一个入口读。
 * 与处置表放在运行时里的理由不同：那张表要在 CR3 装载这条极热的路径上每次都扫，
 * 放在运行时里省一次间接寻址；这张表只在视图违规时才看，那条路径本来就已经做了
 * 远比一次间接寻址更重的事。
 */
static KSW_HVM_INJECT_SLOT g_KswordHvmInjections[KSWORD_ARK_HVM_MAX_INJECTIONS];
static ULONG g_KswordHvmInjectionCount;

/* 往缓冲区里写一个字节并推进游标。 */
static VOID
KswordARKHvmInjectEmit8(
    _Inout_ UCHAR* Buffer,
    _Inout_ ULONG* Cursor,
    _In_ UCHAR Value
    )
{
    Buffer[*Cursor] = Value;
    *Cursor += 1UL;
}

/* 写一段固定字节序列。 */
static VOID
KswordARKHvmInjectEmitBytes(
    _Inout_ UCHAR* Buffer,
    _Inout_ ULONG* Cursor,
    _In_reads_(Length) const UCHAR* Bytes,
    _In_ ULONG Length
    )
{
    RtlCopyMemory(&Buffer[*Cursor], Bytes, Length);
    *Cursor += Length;
}

/* 写一个小端 32 位立即数。 */
static VOID
KswordARKHvmInjectEmit32(
    _Inout_ UCHAR* Buffer,
    _Inout_ ULONG* Cursor,
    _In_ ULONG Value
    )
{
    Buffer[*Cursor + 0UL] = (UCHAR)(Value & 0xFFUL);
    Buffer[*Cursor + 1UL] = (UCHAR)((Value >> 8) & 0xFFUL);
    Buffer[*Cursor + 2UL] = (UCHAR)((Value >> 16) & 0xFFUL);
    Buffer[*Cursor + 3UL] = (UCHAR)((Value >> 24) & 0xFFUL);
    *Cursor += 4UL;
}

/* 写一个小端 64 位立即数。 */
static VOID
KswordARKHvmInjectEmit64(
    _Inout_ UCHAR* Buffer,
    _Inout_ ULONG* Cursor,
    _In_ ULONGLONG Value
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < 8UL; ++index) {
        Buffer[*Cursor + index] =
            (UCHAR)((Value >> (index * 8U)) & 0xFFULL);
    }
    *Cursor += 8UL;
}

/*
 * 在页里找一段足够长的空隙。
 *
 * 只认连续的零字节，并且要求至少 KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES 长：太短
 * 的一段零多半不是节尾填充，而是真代码里恰好连续的零，写进去就是把目标打死。
 *
 * 从页尾往前找。节尾填充在页的后半段，而页的前半段更可能是正在执行的代码——
 * 被劫持的线程此刻的 RIP 就在这一页上。
 */
static BOOLEAN
KswordARKHvmInjectFindCave(
    _In_reads_(KSWORD_ARK_HVM_VIEW_PAGE_BYTES) const UCHAR* Page,
    _In_ ULONG NeededBytes,
    _Out_ ULONG* CaveOffset
    )
{
    ULONG runEnd = KSWORD_ARK_HVM_VIEW_PAGE_BYTES;
    ULONG index = 0UL;

    *CaveOffset = 0UL;
    /* 需要的长度超过一页时无从谈起。 */
    if (NeededBytes == 0UL ||
        NeededBytes > KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
        /* 返回未找到。 */
        return FALSE;
    }
    for (index = KSWORD_ARK_HVM_VIEW_PAGE_BYTES; index > 0UL; --index) {
        if (Page[index - 1UL] != 0U) {
            /* 一段零结束了，看它够不够长。 */
            const ULONG runLength = runEnd - index;

            if (runLength >= NeededBytes &&
                runLength >= KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES) {
                /* 落在这段零的起点上，后面留出的都是空隙。 */
                *CaveOffset = index;
                /* 返回找到。 */
                return TRUE;
            }
            runEnd = index - 1UL;
        }
    }
    /* 整页都是零也算——那多半是一张还没写过的页。 */
    if (runEnd >= NeededBytes &&
        runEnd >= KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES) {
        *CaveOffset = 0UL;
        /* 返回找到。 */
        return TRUE;
    }
    /* 返回未找到。 */
    return FALSE;
}

/*
 * 把外壳与载荷写进影子页的空隙。
 *
 * 外壳做四件事，缺一不可：
 *   1. 保存标志位与全部通用寄存器。被借用的线程正跑在任意一条指令边界上，
 *      载荷动过的任何一个寄存器都会在返回后变成它的错。
 *   2. 对齐栈并留出 32 字节影子空间。Win64 调用约定要求调用点 RSP 十六字节
 *      对齐，而任意指令边界上的 RSP 对齐状态是未知的；不对齐就调用，
 *      被调用方一用 movaps 就 #GP。
 *   3. 跑载荷。
 *   4. 恢复，然后**绝对跳转**回原来那条指令。
 *
 * 第 4 步不用 ret 是硬要求：这台机器上 CET 影子栈开着，压一个没有对应 call 的
 * 返回地址再 ret，会直接吃一个 #CP。DLL 类型里的 call/ret 是配对的，不受影响。
 *
 * 返回用 `jmp rel32`，位移是**指令流里的立即数**，不是从内存读出来的地址。
 * 这一条是实机撞出来的：最初写成 `jmp qword ptr [rip+0]` 加一个八字节返回地址槽，
 * 结果那条 jmp 要**读**紧随其后的八个字节——而 KIND_HOOK 的语义恰恰是"读看真页、
 * 执行跑影子"。槽在影子里被填好了，取到的却是真页上的零，于是跳到地址 0，靶机
 * 蓝屏。取指走影子、数据读走真页这件事，正是这套视图存在的理由，也正是它对
 * 载荷施加的硬约束：**外壳与载荷都不能从被劫持的这一页读数据**。
 *
 * rel32 一定放得下：违规是这一页上的取指故障，所以要跳回去的那条指令与外壳同页，
 * 位移最多几千字节。
 */
static NTSTATUS
KswordARKHvmInjectBuildShell(
    _Inout_updates_(KSWORD_ARK_HVM_VIEW_PAGE_BYTES) UCHAR* Shadow,
    _In_ ULONG CaveOffset,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ ULONG* ShellBytes,
    _Out_ ULONG* ReturnSlotOffset
    )
{
    /* pushfq; push rax,rcx,rdx,rbx,rbp,rsi,rdi */
    static const UCHAR prologueLow[] = {
        0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57
    };
    /* push r8..r15 */
    static const UCHAR prologueHigh[] = {
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
    };
    /* mov rbp,rsp; and rsp,-16; sub rsp,32 */
    static const UCHAR prologueFrame[] = {
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xE4, 0xF0,
        0x48, 0x83, 0xEC, 0x20
    };
    /* mov rsp,rbp */
    static const UCHAR epilogueFrame[] = { 0x48, 0x89, 0xEC };
    /* pop r15..r8 */
    static const UCHAR epilogueHigh[] = {
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58
    };
    /* pop rdi,rsi,rbp,rbx,rdx,rcx,rax; popfq */
    static const UCHAR epilogueLow[] = {
        0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D
    };
    ULONG cursor = CaveOffset;
    ULONG jumpOperandCursor = 0UL;

    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, prologueLow, sizeof(prologueLow));
    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, prologueHigh, sizeof(prologueHigh));
    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, prologueFrame, sizeof(prologueFrame));

    if (Request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) {
        /*
         * 路径在**栈上**现拼，不放在这一页里。
         *
         * 与返回位移同一个理由，而且更致命：LoadLibraryW 要读这个字符串，而这一页
         * 的数据读走的是真页——把路径写进影子，被调用方读到的是真页上的原始
         * 字节。栈是普通可读写内存，不受视图影响。
         *
         * 每八个字节一组，倒序压栈，于是字符串在低地址处按正序排好。组数补成偶数
         * 是为了保持十六字节对齐：上面刚 and rsp,-16 对齐过，奇数组会把它破坏掉，
         * 而被调用方一用 movaps 就 #GP。
         */
        ULONG chunkCount = (Request->payloadBytes + 7UL) / 8UL;
        ULONG chunkIndex = 0UL;

        if ((chunkCount & 1UL) != 0UL) {
            chunkCount += 1UL;
        }
        for (chunkIndex = chunkCount; chunkIndex > 0UL; --chunkIndex) {
            const ULONG offset = (chunkIndex - 1UL) * 8UL;
            ULONGLONG chunk = 0ULL;
            ULONG byteIndex = 0UL;

            for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
                const ULONG sourceIndex = offset + byteIndex;

                /* 超出路径长度的部分补零，同时给字符串留出结尾。 */
                if (sourceIndex < Request->payloadBytes) {
                    chunk |= ((ULONGLONG)Request->payload[sourceIndex]) <<
                        (byteIndex * 8U);
                }
            }
            /* mov rax, imm64 ; push rax */
            KswordARKHvmInjectEmit8(Shadow, &cursor, 0x48U);
            KswordARKHvmInjectEmit8(Shadow, &cursor, 0xB8U);
            KswordARKHvmInjectEmit64(Shadow, &cursor, chunk);
            KswordARKHvmInjectEmit8(Shadow, &cursor, 0x50U);
        }
        /* mov rcx, rsp —— 第一个参数就是刚拼好的那个字符串。 */
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x48U);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x89U);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0xE1U);
        /* sub rsp, 32 —— Win64 要求调用方为被调用方留出影子空间。 */
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x48U);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x83U);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0xECU);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x20U);
        /* mov rax, imm64 —— 调用方解析出来的 LoadLibraryW。 */
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0x48U);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0xB8U);
        KswordARKHvmInjectEmit64(
            Shadow, &cursor, Request->loadLibraryAddress);
        /* call rax。它与自己的 ret 配对，因此不踩 CET 影子栈。 */
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0xFFU);
        KswordARKHvmInjectEmit8(Shadow, &cursor, 0xD0U);
        /* 栈由结尾的 mov rsp,rbp 一次性收回，这里不必逐组弹。 */
    } else {
        /* SHELLCODE：原样写入，寄存器与标志位已经由外壳护住。 */
        KswordARKHvmInjectEmitBytes(
            Shadow, &cursor, Request->payload, Request->payloadBytes);
    }

    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, epilogueFrame, sizeof(epilogueFrame));
    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, epilogueHigh, sizeof(epilogueHigh));
    KswordARKHvmInjectEmitBytes(
        Shadow, &cursor, epilogueLow, sizeof(epilogueLow));
    /*
     * jmp rel32。位移在违规时才知道，这里先留零，把操作数的位置交出去。
     *
     * 不用间接跳转：那要从这一页读数据，而这一页的数据读走的是真页。
     */
    KswordARKHvmInjectEmit8(Shadow, &cursor, 0xE9U);
    jumpOperandCursor = cursor;
    *ReturnSlotOffset = jumpOperandCursor;
    KswordARKHvmInjectEmit32(Shadow, &cursor, 0UL);
    *ShellBytes = cursor - CaveOffset;
    /* 返回完整的外壳构造结果。 */
    return STATUS_SUCCESS;
}

/* 算出外壳加载荷一共要占多少字节。 */
static ULONG
KswordARKHvmInjectNeededBytes(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request
    )
{
    ULONG needed = KSW_HVM_INJECT_PROLOGUE_BYTES +
        KSW_HVM_INJECT_EPILOGUE_BYTES;

    if (Request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) {
        /*
         * DLL 类型不把路径写进页里，而是拆成八字节一组压栈——所以占的是**指令**
         * 空间而不是数据空间，每组十一字节。组数补成偶数以保持十六字节对齐。
         */
        ULONG chunkCount = (Request->payloadBytes + 7UL) / 8UL;

        if ((chunkCount & 1UL) != 0UL) {
            chunkCount += 1UL;
        }
        needed += KSW_HVM_INJECT_CALL_BYTES +
            chunkCount * KSW_HVM_INJECT_PATH_CHUNK_BYTES;
    } else {
        needed += Request->payloadBytes;
    }
    /* 返回完整需求。 */
    return needed;
}

/* 找一条命中给定物理页的注入。退出路径与控制路径共用。 */
static KSW_HVM_INJECT_SLOT*
KswordARKHvmInjectFindByPage(
    _In_ ULONGLONG GuestPhysicalPage
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        KSW_HVM_INJECT_SLOT* slot = &g_KswordHvmInjections[index];

        if (slot->InUse &&
            slot->GuestPhysicalAddress == GuestPhysicalPage) {
            /* 返回命中的那一条。 */
            return slot;
        }
    }
    /* 返回未命中。 */
    return NULL;
}

/* 找一条按 PID 记录的注入。 */
static KSW_HVM_INJECT_SLOT*
KswordARKHvmInjectFindByProcessId(
    _In_ ULONG ProcessId
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        KSW_HVM_INJECT_SLOT* slot = &g_KswordHvmInjections[index];

        if (slot->InUse && slot->ProcessId == ProcessId) {
            /* 返回命中的那一条。 */
            return slot;
        }
    }
    /* 返回未命中。 */
    return NULL;
}

/* 摘掉一条注入占用的视图并清空记录。调用方持运行时锁。 */
static VOID
KswordARKHvmInjectReleaseSlotLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_INJECT_SLOT* Slot
    )
{
    KSWORD_ARK_HVM_VIEW_REQUEST viewRequest = { 0 };
    KSWORD_ARK_HVM_VIEW_RESPONSE viewResponse = { 0 };

    /* 先摘视图再清记录：反过来会丢掉视图标识而泄露一张影子页。 */
    if (Slot->ViewId != 0UL) {
        viewRequest.version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        viewRequest.size = sizeof(viewRequest);
        viewRequest.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        viewRequest.viewId = Slot->ViewId;
        viewRequest.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        viewRequest.confirmationToken =
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        (void)KswordARKHvmEptViewControlLocked(
            Runtime,
            &viewRequest,
            &viewResponse);
    }
    RtlZeroMemory(Slot, sizeof(*Slot));
    if (g_KswordHvmInjectionCount != 0UL) {
        g_KswordHvmInjectionCount -= 1UL;
    }
}

/* 把驱动侧记录填进协议行。 */
static VOID
KswordARKHvmInjectFillRow(
    _In_ const KSW_HVM_INJECT_SLOT* Slot,
    _Out_ KSWORD_ARK_HVM_INJECT_ROW* Row
    )
{
    RtlZeroMemory(Row, sizeof(*Row));
    Row->processId = Slot->ProcessId;
    Row->payloadBytes = Slot->PayloadBytes;
    Row->directoryBase = Slot->DirectoryBase;
    Row->guestLinearAddress = Slot->GuestLinearAddress;
    Row->guestPhysicalAddress = Slot->GuestPhysicalAddress;
    Row->caveOffset = Slot->CaveOffset;
    Row->caveBytes = Slot->CaveBytes;
    Row->executionCount = (ULONGLONG)InterlockedCompareExchange64(
        (volatile LONG64*)&Slot->ExecutionCount, 0LL, 0LL);
    Row->viewId = Slot->ViewId;
}

/* 把整张表写进响应。 */
static VOID
KswordARKHvmInjectPublishTable(
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        const KSW_HVM_INJECT_SLOT* slot = &g_KswordHvmInjections[index];

        if (!slot->InUse) {
            /* 跳过空槽，否则调用方分不清空槽与零计数。 */
            continue;
        }
        KswordARKHvmInjectFillRow(
            slot, &Response->rows[Response->returnedRows]);
        Response->returnedRows += 1UL;
    }
    Response->rowCount = g_KswordHvmInjectionCount;
}

/*
 * 装一次注入。调用方持运行时锁，且已确认常驻停着。
 *
 * 顺序是先读真页、再算空隙、再建影子、最后才装视图并发布记录：任何一步失败都不
 * 留下"记录在表里但视图没装上"的中间态——退出路径会把那种记录当成一次可用的
 * 注入，然后把 RIP 指向一页根本没被替换过的内容。
 */
static NTSTATUS
KswordARKHvmInjectArmLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    )
{
    KSW_HVM_INJECT_SLOT* slot = NULL;
    KSWORD_ARK_HVM_VIEW_REQUEST viewRequest = { 0 };
    KSWORD_ARK_HVM_VIEW_RESPONSE viewResponse = { 0 };
    MM_COPY_ADDRESS copyAddress = { 0 };
    UCHAR* shadow = NULL;
    ULONGLONG directoryBase = 0ULL;
    ULONGLONG guestPhysical = 0ULL;
    ULONGLONG physicalPage = 0ULL;
    SIZE_T copied = 0U;
    ULONG caveOffset = 0UL;
    ULONG shellBytes = 0UL;
    ULONG returnSlotOffset = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 拒绝对 Idle、System 与自己动手。 */
    if (Request->processId == KSW_HVM_INJECT_PID_IDLE ||
        Request->processId == KSW_HVM_INJECT_PID_SYSTEM ||
        Request->processId ==
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET;
        /* 返回明确的目标拒绝。 */
        return STATUS_ACCESS_DENIED;
    }
    /* 校验类型与长度。 */
    if ((Request->injectType != KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE &&
         Request->injectType != KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) ||
        Request->payloadBytes == 0UL ||
        Request->payloadBytes >
            KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES ||
        Request->guestLinearAddress == 0ULL ||
        (Request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH &&
         Request->loadLibraryAddress == 0ULL)) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 作用域靠 CR3-load exiting，缺了拒绝而不是降级成全机器生效。 */
    if ((Runtime->CrPolicyFlags &
            KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED;
        /* 返回明确的前提缺失。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 执行视图由 EPTP 切换后端提供。 */
    if (!Runtime->EptpSwitchArmed) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED;
        /* 返回明确的前提缺失。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 同一个进程只允许一条，否则第二条的视图会与第一条抢同一张叶。 */
    if (KswordARKHvmInjectFindByProcessId(Request->processId) != NULL) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED;
        /* 返回明确的重复安装拒绝。 */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* 取一个空槽，满了就在什么都还没做时拒绝。 */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        if (!g_KswordHvmInjections[index].InUse) {
            slot = &g_KswordHvmInjections[index];
            break;
        }
    }
    if (slot == NULL) {
        Response->status = KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL;
        /* 返回明确的容量耗尽。 */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* 解析目标进程真正在用的层次基址。 */
    status = KswordARKHvmMemoryResolveProcessDirectoryBase(
        Request->processId,
        &directoryBase);
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED;
        Response->lastStatus = status;
        /* 返回明确的进程解析失败。 */
        return status;
    }
    directoryBase &= KSW_HVM_INJECT_CR3_FRAME_MASK;
    /* 把要劫持的那一页翻译成客户物理地址。 */
    status = KswordARKHvmMemoryTranslate(
        directoryBase,
        Request->guestLinearAddress,
        &guestPhysical);
    if (!NT_SUCCESS(status)) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED;
        Response->lastStatus = status;
        /* 返回明确的翻译失败。 */
        return status;
    }
    physicalPage = guestPhysical & KSW_HVM_INJECT_PAGE_MASK;
    /*
     * 影子先在非分页内存里拼好，再交给视图后端。
     *
     * 不直接改真页：KIND_HOOK 的全部意义就是真页一个字节都不动，读它的人看到的
     * 仍然是原始内容。
     */
    shadow = (UCHAR*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
        'jnIK');
    if (shadow == NULL) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED;
        Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* 返回明确的资源失败。 */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* 影子以真页的完整副本起步，空隙之外的每一个字节都必须原样保留。 */
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalPage;
    status = MmCopyMemory(
        shadow,
        copyAddress,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
        MM_COPY_MEMORY_PHYSICAL,
        &copied);
    if (!NT_SUCCESS(status) ||
        copied != (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
        ExFreePool(shadow);
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED;
        Response->lastStatus =
            NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        /* 返回明确的取页失败。 */
        return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }
    /* 找空隙。找不到就在装任何东西之前拒绝。 */
    if (!KswordARKHvmInjectFindCave(
            shadow,
            KswordARKHvmInjectNeededBytes(Request),
            &caveOffset)) {
        ExFreePool(shadow);
        Response->status = KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE;
        /* 返回明确的空隙不足。 */
        return STATUS_NOT_FOUND;
    }
    status = KswordARKHvmInjectBuildShell(
        shadow,
        caveOffset,
        Request,
        &shellBytes,
        &returnSlotOffset);
    if (!NT_SUCCESS(status)) {
        ExFreePool(shadow);
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        Response->lastStatus = status;
        /* 返回明确的外壳构造失败。 */
        return status;
    }
    /* 装执行视图：读写看真页，执行跑影子。 */
    viewRequest.version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    viewRequest.size = sizeof(viewRequest);
    viewRequest.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    viewRequest.kind = KSWORD_ARK_HVM_VIEW_KIND_HOOK;
    viewRequest.physicalAddress = physicalPage;
    viewRequest.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
    viewRequest.confirmationToken =
        KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    RtlCopyMemory(
        viewRequest.shadow,
        shadow,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
    ExFreePool(shadow);
    status = KswordARKHvmEptViewControlLocked(
        Runtime,
        &viewRequest,
        &viewResponse);
    if (!NT_SUCCESS(status) ||
        viewResponse.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        Response->status = KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED;
        Response->lastStatus = viewResponse.lastStatus;
        /* 返回明确的视图安装失败。 */
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    /* 全部就绪之后才发布记录。 */
    slot->ProcessId = Request->processId;
    slot->PayloadBytes = Request->payloadBytes;
    slot->CaveOffset = caveOffset;
    slot->CaveBytes = shellBytes;
    slot->ReturnSlotOffset = returnSlotOffset;
    slot->ViewId = viewResponse.viewId;
    slot->DirectoryBase = directoryBase;
    slot->GuestPhysicalAddress = physicalPage;
    slot->GuestLinearAddress =
        Request->guestLinearAddress & KSW_HVM_INJECT_PAGE_MASK;
    slot->ExecutionCount = 0LL;
    slot->Fired = FALSE;
    /* InUse 最后置位：退出路径靠它判断这一条是否可用。 */
    slot->InUse = TRUE;
    g_KswordHvmInjectionCount += 1UL;
    Response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
    /* 返回完整的安装成功。 */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmInjectControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->generation = Runtime->Generation;
    Response->stateFlags = (ULONGLONG)Runtime->StateFlags;
    if (Request->version != KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    switch (Request->operation) {
    case KSWORD_ARK_HVM_INJECT_OP_QUERY:
        Response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        break;
    case KSWORD_ARK_HVM_INJECT_OP_ARM:
        status = KswordARKHvmInjectArmLocked(Runtime, Request, Response);
        break;
    case KSWORD_ARK_HVM_INJECT_OP_RELEASE: {
        KSW_HVM_INJECT_SLOT* slot =
            KswordARKHvmInjectFindByProcessId(Request->processId);

        if (slot == NULL) {
            Response->status = KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND;
            status = STATUS_NOT_FOUND;
        } else {
            KswordARKHvmInjectReleaseSlotLocked(Runtime, slot);
            Response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        }
        break;
    }
    case KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL:
        KswordARKHvmInjectResetLocked(Runtime);
        Response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        break;
    default:
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    KswordARKHvmInjectPublishTable(Response);
    Response->generation = Runtime->Generation;
    /* 返回完整的操作结果。 */
    return status;
}

NTSTATUS
KswordARKHvmInjectControl(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    )
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || Response == NULL || runtime == NULL) {
        /* 返回明确的契约失败。 */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * 只有安装受"常驻停着"的限制。
     *
     * 安装要分页、要装视图，那些都是退出路径不持锁在读的东西。撤销只摘视图与清
     * 记录，视图后端自己会拒绝在常驻期间摘——所以这里放行，由它去拒绝并给出
     * 属于它的理由，而不是在这里用一个更笼统的码把它盖掉。
     */
    mutating = Request->operation == KSWORD_ARK_HVM_INJECT_OP_ARM;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    if (!runtime->Initialized) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        Response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        status = STATUS_SUCCESS;
    } else {
        status = KswordARKHvmInjectControlLocked(
            runtime,
            Request,
            Response);
    }
    ExReleasePushLockExclusive(&runtime->Lock);
    KeLeaveCriticalRegion();
    /* 返回完整的操作结果。 */
    return status;
}

BOOLEAN
KswordARKHvmInjectHijackRip(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ ULONGLONG GuestCr3,
    _In_ ULONGLONG GuestRip,
    _Out_ ULONGLONG* NewRip
    )
{
    KSW_HVM_INJECT_SLOT* slot = NULL;
    volatile UCHAR* shadow = NULL;

    if (Runtime == NULL || NewRip == NULL) {
        /* 返回不劫持。 */
        return FALSE;
    }
    *NewRip = 0ULL;
    /* 表空时直接返回，省掉每次视图违规的一次扫描。 */
    if (g_KswordHvmInjectionCount == 0UL) {
        /* 返回不劫持。 */
        return FALSE;
    }
    /*
     * 只认取指违规。读写违规也会走视图路径，但那时客户机并没有要执行这一页，
     * 把 RIP 指过去就是凭空改变一条与本次访问无关的执行流。
     */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        /* 返回不劫持。 */
        return FALSE;
    }
    slot = KswordARKHvmInjectFindByPage(
        GuestPhysicalAddress & KSW_HVM_INJECT_PAGE_MASK);
    if (slot == NULL || slot->Fired) {
        /* 返回不劫持。 */
        return FALSE;
    }
    /*
     * 作用域检查不能省。
     *
     * 视图装在客户物理页上，全机器可见；同一张物理页可能被多个进程映射（共享的
     * 镜像节就是这样）。不比 CR3 的话，任何一个执行到这一页的进程都会被拖去跑
     * 载荷——那既不是调用方要的，也会把载荷跑在一个完全没准备的上下文里。
     */
    if ((GuestCr3 & KSW_HVM_INJECT_CR3_FRAME_MASK) !=
            slot->DirectoryBase) {
        /* 返回不劫持。 */
        return FALSE;
    }
    /*
     * 把返回位移回填进影子页里那条 jmp rel32 的操作数。
     *
     * 影子是驱动自己分配的非分页内存，任何 IRQL 下都能碰。写的是"载荷跑完要跳
     * 回哪里"——也就是客户机本来要执行的那条指令。这一步必须在改 RIP 之前完成：
     * 顺序反了而中间失败，客户机会跳到一个位移还是零的地方。
     *
     * rel32 的基准是**下一条指令**的地址，也就是操作数之后。两端都在同一页上，
     * 所以位移必然放得下三十二位。
     */
    shadow = KswordARKHvmEptViewShadowForViewId(Runtime, slot->ViewId);
    if (shadow == NULL) {
        /* 返回不劫持：没有影子就没有可回填的位移。 */
        return FALSE;
    }
    {
        const ULONGLONG nextInstruction = slot->GuestLinearAddress +
            (ULONGLONG)slot->ReturnSlotOffset + 4ULL;
        const LONG displacement =
            (LONG)(LONG64)(GuestRip - nextInstruction);
        ULONG index = 0UL;

        for (index = 0UL; index < 4UL; ++index) {
            shadow[slot->ReturnSlotOffset + index] =
                (UCHAR)(((ULONG)displacement >> (index * 8U)) & 0xFFUL);
        }
    }
    /* 一次性：置位之后同一页的后续违规按普通视图切换处理。 */
    slot->Fired = TRUE;
    InterlockedIncrement64(&slot->ExecutionCount);
    *NewRip = slot->GuestLinearAddress + (ULONGLONG)slot->CaveOffset;
    /* 返回劫持。 */
    return TRUE;
}

VOID
KswordARKHvmInjectResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    if (Runtime == NULL) {
        /* 无事可做。 */
        return;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        if (g_KswordHvmInjections[index].InUse) {
            KswordARKHvmInjectReleaseSlotLocked(
                Runtime,
                &g_KswordHvmInjections[index]);
        }
    }
    g_KswordHvmInjectionCount = 0UL;
}

#endif /* _M_AMD64 */
