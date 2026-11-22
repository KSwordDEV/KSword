#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QString>

class QWidget;
struct ThreadStackTarget;

// 只读线程查询的回执；失败原因与实际驱动响应分别保存。
struct VerifiedThreadDetail
{
    bool verified = false; // 传输、原线程身份及响应身份均匹配时为真。
    QString diagnostic; // 无法验证或读取时的简短说明。
    KSWORD_ARK_THREAD_DETAIL_RESPONSE response{}; // 固定协议响应，不含调用帧。
};

// 在工作线程调用；持有经过创建时间核对的对象句柄，仅请求指定字段组。
VerifiedThreadDetail QueryVerifiedThreadDetail(const ThreadStackTarget& target, unsigned long flags);

// 在 GUI 线程调用；从冻结的线程身份打开同一个对象详情页，不改变源列表选择。
void ShowThreadDetailWindow(QWidget* parent, const ThreadStackTarget& target);
