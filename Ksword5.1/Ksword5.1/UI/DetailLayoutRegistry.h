#pragma once

// ============================================================
// DetailLayoutRegistry.h
// 作用：
// - 保存全局详情显示方案；
// - 对已创建页面即时广播方案；
// - 让后续懒加载页面注册时直接采用最新方案。
// ============================================================

#include "../SettingsDock/AppearanceSettings.h"

class CodeEditorWidget;
class QAbstractItemView;
class QWidget;
class QSplitter;

namespace ks::ui
{
    class DetailLayoutHost;

    class DetailLayoutRegistry final
    {
    public:
        // registerHost：注册一个严格命中页面并返回其控制器；重复注册同一编辑器时复用旧控制器。
        static DetailLayoutHost* registerHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget);

        // 显式注册：splitter 的两个直接面板由页面指定，不推断现有控件层级。
        static DetailLayoutHost* registerHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget,
            QSplitter* splitter,
            QWidget* mainPane,
            QWidget* detailPane);

        // applyGlobalScheme：更新全局方案并立即重排全部仍存活页面。
        static void applyGlobalScheme(ks::settings::DetailDisplayScheme scheme);

        // globalScheme：返回当前全局方案，供懒加载页面注册时使用。
        static ks::settings::DetailDisplayScheme globalScheme();

        // hostFor / prepareDataRebuild：按原详情编辑器定位页面控制器，并在业务数据重建前清理合成行。
        static DetailLayoutHost* hostFor(CodeEditorWidget* detailEditor);
        static void prepareDataRebuild(CodeEditorWidget* detailEditor);

    private:
        DetailLayoutRegistry() = delete;
    };
}
