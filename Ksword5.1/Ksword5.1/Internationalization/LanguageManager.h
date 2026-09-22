#pragma once

#include <QList>
#include <QHash>
#include <QObject>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include <memory>

class QComboBox;
class QLineEdit;
class QSpinBox;
class QTabWidget;
class QWidget;

namespace ks::i18n
{
    struct LanguageInfo
    {
        QString id;
        QString name;
        QString nativeName;
        QString author;
        QString filePath;
        bool rightToLeft = false;
    };

    class LanguageManager final : public QObject
    {
    public:
        static LanguageManager& instance();

        bool initialize(const QString& preferredLanguageId, QString* errorTextOut = nullptr);
        bool setLanguage(const QString& languageId, QString* errorTextOut = nullptr);

        QString currentLanguageId() const;
        QList<LanguageInfo> availableLanguages() const;
        QString text(const QString& key, const QString& fallbackText = QString()) const;
        QString contextText(const QString& contextKey, const QString& sourceText) const;
        QString sourceText(const QString& sourceText) const;
        // 强制查询当前语言包的 source_translations；用于以英文作为规范源文本的独立页面。
        // 与 sourceText() 不同，中文模式下也会查包，而不是直接返回调用点文本。
        QString packedSourceText(const QString& sourceText) const;
        QString sourceForRenderedText(const QString& renderedText) const;
        QString displayText(const QString& renderedOrSourceText) const;

        void bindText(QObject* object, const QString& key, const QString& fallbackText);
        void bindToolTip(QWidget* widget, const QString& key, const QString& fallbackText);
        void bindPlaceholder(QLineEdit* lineEdit, const QString& key, const QString& fallbackText);
        void bindSuffix(QSpinBox* spinBox, const QString& key, const QString& fallbackText);
        void bindWindowTitle(QWidget* widget, const QString& key, const QString& fallbackText);
        void bindTab(QTabWidget* tabWidget, QWidget* page, const QString& key, const QString& fallbackText);
        void bindTabToolTip(QTabWidget* tabWidget, QWidget* page, const QString& key, const QString& fallbackText);
        void bindComboBoxItem(
            QComboBox* comboBox,
            int itemIndex,
            const QString& key,
            const QString& fallbackText);
        void retranslateAll();

    private:
        LanguageManager();
        ~LanguageManager() override;
        Q_DISABLE_COPY_MOVE(LanguageManager)

        // 语言包按需加载：启动只读取每个包的元数据清单，翻译表在第一次真正用到时才解析。
        // State 持有清单与已加载的翻译表；PackRef 是一次查询拿到的只读快照。
        struct State;
        struct PackRef;

        void discoverLanguagePacks(QStringList* warningListOut);
        // acquirePack：按语言 id 取包；尚未加载时在此处解析。找不到或解析失败时 data 为空。
        PackRef acquirePack(const QString& languageId) const;
        // hasAnyPack：清单里是否有可用语言包；只看元数据，不触发加载。
        bool hasAnyPack() const;
        QString resolvePreferredLanguageId(const QString& preferredLanguageId) const;
        QString resolveText(
            const QString& languageId,
            const QString& key,
            const QString& fallbackText,
            QStringList* visitedLanguageIds) const;
        QString resolveContextText(
            const QString& languageId,
            const QString& contextKey,
            const QString& sourceText,
            QStringList* visitedLanguageIds) const;
        QString resolveSourceText(
            const QString& languageId,
            const QString& sourceText,
            QStringList* visitedLanguageIds,
            bool preserveHistoricalChineseSource) const;
        void ensureApplicationEventFilter();
        void scheduleRuntimeTranslation(QObject* object);
        void applyRuntimeTranslations(QObject* object);
        void applyBindings(QObject* object) const;
        void applyApplicationDirection() const;
        bool eventFilter(QObject* watched, QEvent* event) override;

        std::unique_ptr<State> m_state;
        QString m_currentLanguageId;
        bool m_applicationEventFilterInstalled = false;
        bool m_applyingRuntimeTranslations = false;
    };

    inline QString text(const QString& key, const QString& fallbackText = QString())
    {
        return LanguageManager::instance().text(key, fallbackText);
    }

    inline QString contextText(const QString& contextKey, const QString& sourceText)
    {
        return LanguageManager::instance().contextText(contextKey, sourceText);
    }

    inline QString sourceText(const QString& sourceText)
    {
        return LanguageManager::instance().sourceText(sourceText);
    }

    inline QString packedSourceText(const QString& sourceText)
    {
        return LanguageManager::instance().packedSourceText(sourceText);
    }

    inline QString displayText(const QString& renderedOrSourceText)
    {
        return LanguageManager::instance().displayText(renderedOrSourceText);
    }

}
