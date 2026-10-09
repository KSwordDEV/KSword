#pragma once

// HvmWatchEventDialog：一条内存监视命中事件的现场详情。
//
// 为什么监视表自己的详情面板不够：
//
// 驱动在命中那一刻往两个地方各写了一份。一份写进 watch 记录本身（RIP / RSP /
// CR3 / GLA / GPA / 时间 / CPU），那是为了在事件环回绕之后仍然答得出"被动过"；
// 另一份写进事件环，那一份**多一个字段**——qualification，也就是处理器给出的
// EPT violation 退出限定符。它是"这次访问到底是读、是写、还是取指，页当时还剩
// 哪些权限，线性地址有没有效"的原始读数，watch 记录里没有它。
//
// 所以这个窗口不是把面板上已有的东西换个地方再显示一遍，它回答的是面板答不了
// 的那一段。
//
// 另一件它必须说清楚的事：**事件可能已经不在环里了**。环是有界的，VMX root 里
// 从不等待，所以它会丢。"事件取不回来"与"目标没被访问过"在界面上极容易长成
// 同一句话，而这两句话的结论正好相反。这个窗口因此把查询结果分成四态显示，
// 绝不把它们压成一个"无事件"。

#include <QString>
#include "StructuredFieldView.h"

namespace ksword::hvm
{
    struct HvmWatchEntry;
    struct HvmWatchHitEvent;
}

class QWidget;

namespace ks::ui
{
    // showWatchHitEvent：显示一次命中的完整现场。
    //
    // 参数：
    //   parent —— 弹窗归属的窗口，为空时弹窗无父窗口。
    //   entry  —— 监视表快照里的那一行，提供目标与监视自己保留的现场。
    //   hit    —— ksword::hvm::findWatchHitEvent 的结果，四态之一。
    //   label  —— 目标的人话描述，空串表示这条监视没有标签。
    //
    // 返回：无。窗口是模态的——用户此刻在看一条具体证据，不该同时去点别处。
    //
    // 调用方负责在后台线程里先取得 hit：findWatchHitEvent 走阻塞 IOCTL，
    // 在 UI 线程直接调会把界面卡住。这个函数本身只做展示，不发任何 IOCTL。
    void showWatchHitEvent(
        QWidget* parent,
        const ksword::hvm::HvmWatchEntry& entry,
        const ksword::hvm::HvmWatchHitEvent& hit,
        const QString& label);

    // buildWatchHitDocument：从事件快照构建唯一字段模型。
    //
    // 单独暴露是因为"复制证据"与"导出全部证据"要的就是同一段文字：另拼一份
    // 会让窗口里看到的与复制出去的随时间漂开，而证据最不能有的就是两个版本。
    FieldDocument buildWatchHitDocument(
        const ksword::hvm::HvmWatchEntry& entry,
        const ksword::hvm::HvmWatchHitEvent& hit,
        const QString& label);
}
