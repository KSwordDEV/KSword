#include "WindowTargetPicker.h"

#include "AsyncOperation.h"
#include "SecondaryPageLayout.h"
#include "ThemeBinding.h"
#include "UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QGraphicsItem>
#include <QGraphicsScene>
#include <QGraphicsSceneHoverEvent>
#include <QGraphicsSceneMouseEvent>
#include <QGraphicsView>
#include <QFocusEvent>
#include <QImage>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QScreen>
#include <QTimer>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <QWindow>
#include <QIcon>
#include <QTextDocument>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <windows.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <roapi.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <winrt/Windows.Foundation.Metadata.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "windowsapp.lib")
#pragma comment(lib, "shell32.lib")

namespace ks::ui
{
    namespace
    {
        QString text(const char* key, const char* source)
        {
            return ks::i18n::contextText(QString::fromLatin1(key), QString::fromUtf8(source));
        }

        class PhysicalCoordinates final
        {
        public:
            PhysicalCoordinates()
                : m_previous(::SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {}
            ~PhysicalCoordinates() { if (m_previous) ::SetThreadDpiAwarenessContext(m_previous); }
        private:
            DPI_AWARENESS_CONTEXT m_previous;
        };

        struct Candidate
        {
            quintptr hwnd = 0;
            DWORD pid = 0;
            DWORD tid = 0;
            QString title;
            QString processName;
            QImage processIcon;
        };

        struct ProcessPresentation { QString name; QImage icon; };
        ProcessPresentation processPresentation(DWORD pid)
        {
            ProcessPresentation result;
            const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!process) return result;
            wchar_t path[32768]{};
            DWORD length = static_cast<DWORD>(std::size(path));
            const bool queried = ::QueryFullProcessImageNameW(process, 0, path, &length) != FALSE;
            ::CloseHandle(process);
            if (!queried) return result;
            const QString imagePath = QString::fromWCharArray(path, static_cast<int>(length));
            result.name = imagePath.mid(imagePath.lastIndexOf(QLatin1Char('\\')) + 1);
            // Match the list pages: Shell work stays on the worker, and only
            // owned QImage pixels cross back to the graphics scene.
            SHFILEINFOW info{};
            if (::SHGetFileInfoW(path, 0, &info, sizeof(info), SHGFI_ICON | SHGFI_LARGEICON) && info.hIcon)
            {
                result.icon = QImage::fromHICON(info.hIcon);
                ::DestroyIcon(info.hIcon);
            }
            return result;
        }

        bool stillValid(const Candidate& value)
        {
            DWORD pid = 0;
            const auto tid = ::GetWindowThreadProcessId(reinterpret_cast<HWND>(value.hwnd), &pid);
            return tid != 0 && tid == value.tid && pid == value.pid;
        }

        struct EnumerationRequest { QPoint point; quintptr excluded; };
        std::vector<Candidate> enumerate(const EnumerationRequest& request, const AsyncOperationToken& token)
        {
            const PhysicalCoordinates coordinates;
            std::vector<Candidate> result;
            std::unordered_set<HWND> visited;
            std::unordered_map<DWORD, ProcessPresentation> processes;
            struct ShellApartment
            {
                HRESULT result = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                ~ShellApartment() { if (SUCCEEDED(result)) ::CoUninitialize(); }
            } apartment;
            const POINT point{request.point.x(), request.point.y()};
            // Follow the actual top-to-bottom Z chain; protect traversal against
            // windows being destroyed/reordered during this one-shot snapshot.
            for (HWND hwnd = ::GetTopWindow(nullptr); hwnd && visited.insert(hwnd).second;
                hwnd = ::GetWindow(hwnd, GW_HWNDNEXT))
            {
                if (token.isCanceled()) break;
                if (reinterpret_cast<quintptr>(hwnd) == request.excluded || !::IsWindowVisible(hwnd)
                    || ::IsIconic(hwnd) || hwnd == ::GetDesktopWindow() || hwnd == ::GetShellWindow()) continue;
                DWORD cloaked = 0;
                if (SUCCEEDED(::DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked))) && cloaked) continue;
                RECT bounds{};
                if (FAILED(::DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &bounds, sizeof(bounds)))
                    && !::GetWindowRect(hwnd, &bounds)) continue;
                if (!::PtInRect(&bounds, point)) continue;
                Candidate value;
                value.hwnd = reinterpret_cast<quintptr>(hwnd);
                value.tid = ::GetWindowThreadProcessId(hwnd, &value.pid);
                if (!value.tid || !value.pid) continue;
                wchar_t title[2048]{};
                ::GetWindowTextW(hwnd, title, static_cast<int>(std::size(title)));
                if (!title[0]) ::GetClassNameW(hwnd, title, static_cast<int>(std::size(title)));
                value.title = QString::fromWCharArray(title);
                auto process = processes.find(value.pid);
                if (process == processes.end())
                    process = processes.emplace(value.pid, processPresentation(value.pid)).first;
                value.processName = process->second.name;
                value.processIcon = process->second.icon;
                result.push_back(std::move(value));
            }
            return result;
        }

        enum class CaptureState { Loading, Ready, Unavailable, Restricted, Closed };
        struct Snapshot { QImage image; CaptureState state = CaptureState::Unavailable; };

        // A single WGC frame captures the window's own composition, including
        // occluded content. No screen BitBlt or blocking foreign WM_PRINT call.
        Snapshot capture(const Candidate& value, const AsyncOperationToken& token)
        {
            using namespace winrt::Windows::Graphics;
            using namespace winrt::Windows::Graphics::Capture;
            if (!stillValid(value)) return {{}, CaptureState::Closed};
            const HWND hwnd = reinterpret_cast<HWND>(value.hwnd);
            DWORD affinity = 0;
            if (::GetWindowDisplayAffinity(hwnd, &affinity) && affinity != WDA_NONE)
                return {{}, CaptureState::Restricted};
            struct Apartment
            {
                HRESULT result = ::RoInitialize(RO_INIT_MULTITHREADED);
                ~Apartment() { if (SUCCEEDED(result)) ::RoUninitialize(); }
            } apartment;
            if (FAILED(apartment.result)) return {};
            struct Session
            {
                GraphicsCaptureSession session{nullptr};
                Direct3D11CaptureFramePool pool{nullptr};
                ~Session()
                {
                    try { if (session) session.Close(); } catch (...) {}
                    try { if (pool) pool.Close(); } catch (...) {}
                }
            } resources;
            try
            {
                if (!GraphicsCaptureSession::IsSupported() || token.isCanceled()) return {};
                const auto factory = winrt::get_activation_factory<GraphicsCaptureItem, IGraphicsCaptureItemInterop>();
                GraphicsCaptureItem item{nullptr};
                winrt::check_hresult(factory->CreateForWindow(hwnd,
                    winrt::guid_of<GraphicsCaptureItem>(), winrt::put_abi(item)));
                const auto size = item.Size();
                if (size.Width <= 0 || size.Height <= 0) return {};
                winrt::com_ptr<ID3D11Device> device;
                winrt::com_ptr<ID3D11DeviceContext> context;
                HRESULT created = ::D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION,
                    device.put(), nullptr, context.put());
                if (FAILED(created))
                    created = ::D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
                        D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION,
                        device.put(), nullptr, context.put());
                winrt::check_hresult(created);
                const auto dxgi = device.as<IDXGIDevice>();
                winrt::com_ptr<IInspectable> inspectable;
                winrt::check_hresult(::CreateDirect3D11DeviceFromDXGIDevice(dxgi.get(), inspectable.put()));
                const auto projected = inspectable.as<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>();
                resources.pool = Direct3D11CaptureFramePool::CreateFreeThreaded(projected,
                    winrt::Windows::Graphics::DirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized, 1, size);
                resources.session = resources.pool.CreateCaptureSession(item);
                using winrt::Windows::Foundation::Metadata::ApiInformation;
                if (ApiInformation::IsPropertyPresent(L"Windows.Graphics.Capture.GraphicsCaptureSession", L"IsCursorCaptureEnabled"))
                    resources.session.IsCursorCaptureEnabled(false);
                resources.session.StartCapture();
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(700);
                while (!token.isCanceled() && std::chrono::steady_clock::now() < deadline)
                {
                    auto frame = resources.pool.TryGetNextFrame();
                    if (!frame) { ::Sleep(10); continue; }
                    const auto access = frame.Surface().as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
                    winrt::com_ptr<ID3D11Texture2D> texture;
                    winrt::check_hresult(access->GetInterface(__uuidof(ID3D11Texture2D), texture.put_void()));
                    D3D11_TEXTURE2D_DESC description{};
                    texture->GetDesc(&description);
                    const auto content = frame.ContentSize();
                    const int width = (std::min)(content.Width, static_cast<int>(description.Width));
                    const int height = (std::min)(content.Height, static_cast<int>(description.Height));
                    if (width <= 0 || height <= 0) return {};
                    description.Usage = D3D11_USAGE_STAGING;
                    description.BindFlags = 0;
                    description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                    description.MiscFlags = 0;
                    winrt::com_ptr<ID3D11Texture2D> staging;
                    winrt::check_hresult(device->CreateTexture2D(&description, nullptr, staging.put()));
                    context->CopyResource(staging.get(), texture.get());
                    D3D11_MAPPED_SUBRESOURCE mapped{};
                    winrt::check_hresult(context->Map(staging.get(), 0, D3D11_MAP_READ, 0, &mapped));
                    QImage image(width, height, QImage::Format_RGB32);
                    if (!image.isNull())
                        for (int row = 0; row < height; ++row)
                            std::memcpy(image.scanLine(row), static_cast<const BYTE*>(mapped.pData)
                                + static_cast<std::size_t>(row) * mapped.RowPitch, static_cast<std::size_t>(width) * 4);
                    context->Unmap(staging.get(), 0);
                    frame.Close();
                    if (!stillValid(value)) return {{}, CaptureState::Closed};
                    if (image.isNull()) return {};
                    image = image.scaled(QSize(1100, 760), Qt::KeepAspectRatio, Qt::SmoothTransformation);
                    return {std::move(image), CaptureState::Ready};
                }
            }
            catch (const winrt::hresult_error&) { return {}; }
            return {};
        }

        QString stateText(CaptureState state)
        {
            switch (state)
            {
            case CaptureState::Loading: return text("window.picker.loading_image", "正在捕获静态预览…");
            case CaptureState::Ready: return {};
            case CaptureState::Restricted: return text("window.picker.restricted", "窗口限制截图；仍可点击选择");
            case CaptureState::Closed: return text("window.picker.closed", "窗口已关闭，请重新拾取");
            default: return text("window.picker.unavailable", "无法捕获此窗口；仍可点击选择");
            }
        }

        constexpr qreal PreviewOpacity = .60;
        QTransform planeProjection(bool active = false)
        {
            // Upper edge leans right; keep the projected left bound at zero.
            // The depth axis stays half length at both 45 and 60 degrees.
            const qreal horizontal = active ? .25 : .353553390593;
            const qreal vertical = active ? .433012701892 : .353553390593;
            return QTransform(1, 0, -horizontal, vertical, 440 * horizontal, 0);
        }
        QPointF layerPosition(std::size_t index)
        {
            return QPointF(0, static_cast<qreal>(index) * 88);
        }

        class PreviewItem;
        class PreviewScene final : public QGraphicsScene
        {
        public:
            using QGraphicsScene::QGraphicsScene;
            void highlight(PreviewItem* item);
            PreviewItem* highlighted() const { return m_highlighted; }
        private:
            PreviewItem* m_highlighted = nullptr;
        };

        class PreviewItem final : public QGraphicsItem
        {
        public:
            Candidate candidate;
            Snapshot snapshot{{}, CaptureState::Loading};
            std::function<void()> picked;
            std::function<void()> hovered;
            PreviewItem()
            {
                setAcceptHoverEvents(true);
                setAcceptedMouseButtons(Qt::LeftButton);
                setFlag(ItemIsFocusable);
                m_polygon = planeProjection().map(QPolygonF(QRectF(0, 0, 680, 440)));
                m_activePolygon = planeProjection(true).map(QPolygonF(QRectF(0, 0, 680, 440)));
            }
            ~PreviewItem() override
            {
                if (auto* host = dynamic_cast<PreviewScene*>(scene()); host && host->highlighted() == this)
                    host->highlight(nullptr);
            }
            QRectF informationRect() const
            { return QRectF(m_polygon.boundingRect().right() + 24, 38, 300, 80); }
            QRectF previewRect() const { return m_polygon.boundingRect(); }
            bool highlighted() const
            {
                const auto* host = dynamic_cast<const PreviewScene*>(scene());
                return host && host->highlighted() == this;
            }
            QRectF boundingRect() const override
            {
                return m_polygon.boundingRect().united(m_activePolygon.boundingRect())
                    .adjusted(-5, -5, 5, 5).united(informationRect());
            }
            QPainterPath shape() const override
            {
                QPainterPath path;
                path.addPolygon(m_polygon);
                path.closeSubpath();
                if (highlighted())
                {
                    QPainterPath active;
                    active.addPolygon(m_activePolygon);
                    active.closeSubpath();
                    // Retain the entry footprint while inspecting the tilted
                    // plane, so a stationary pointer cannot oscillate hover.
                    path = path.united(active);
                }
                path.addRect(informationRect());
                return path;
            }
            void paint(QPainter* painter, const QStyleOptionGraphicsItem*, QWidget*) override
            {
                painter->setRenderHint(QPainter::Antialiasing);
                const bool active = highlighted();
                const QPolygonF& polygon = active ? m_activePolygon : m_polygon;
                painter->save();
                painter->setTransform(planeProjection(active), true);
                painter->setOpacity(active ? 1.0 : PreviewOpacity);
                if (!snapshot.image.isNull())
                {
                    const QSizeF fitted = QSizeF(snapshot.image.size()).scaled(QSizeF(680, 440), Qt::KeepAspectRatio);
                    const QRectF imageRect(QPointF((680 - fitted.width()) / 2, (440 - fitted.height()) / 2), fitted);
                    QPainterPath backing, content;
                    backing.addRect(QRectF(0, 0, 680, 440));
                    content.addRect(imageRect);
                    // Do not put a second translucent fill under image pixels:
                    // two 60% layers would become 84% opaque.
                    painter->fillPath(backing.subtracted(content), KswordTheme::SurfaceColor());
                    painter->drawImage(imageRect, snapshot.image);
                }
                else painter->fillRect(QRectF(0, 0, 680, 440), KswordTheme::SurfaceColor());
                painter->restore();
                if (active)
                {
                    QPen halo(KswordTheme::MaximumContrastMonochromeColor(KswordTheme::PrimaryAccentColor()));
                    halo.setCosmetic(true);
                    halo.setWidth(5);
                    painter->setPen(halo);
                    painter->setBrush(Qt::NoBrush);
                    painter->drawPolygon(polygon);
                }
                QPen edge(active ? KswordTheme::PrimaryAccentColor() : KswordTheme::BorderColor());
                edge.setCosmetic(true);
                edge.setWidth(active ? 3 : 1);
                painter->setPen(edge);
                painter->setBrush(Qt::NoBrush);
                painter->drawPolygon(polygon);
                // Metadata occupies a separate aligned column outside the
                // projected screenshots. Only screenshot pixels are translucent.
                const QRectF label = informationRect();
                const QColor surface = KswordTheme::SurfaceColor();
                painter->fillRect(label, surface);
                painter->setPen(KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), surface));
                const auto drawLine = [&](const QRectF& area, const QString& line) {
                    painter->drawText(area, Qt::AlignVCenter,
                        painter->fontMetrics().elidedText(line, Qt::ElideRight, qRound(area.width())));
                };
                drawLine(QRectF(label.left(), label.top(), label.width(), 20), candidate.title);
                const QRectF icon(label.left(), label.top() + 24, 24, 24);
                if (!candidate.processIcon.isNull()) painter->drawImage(icon, candidate.processIcon);
                else
                {
                    static const QIcon fallback(QStringLiteral(":/Icon/process_main.svg"));
                    fallback.paint(painter, icon.toRect());
                }
                drawLine(QRectF(label.left() + 32, label.top() + 22, label.width() - 32, 22),
                    candidate.processName.isEmpty() ? text("window.picker.process_unknown", "进程名不可用") : candidate.processName);
                drawLine(QRectF(label.left() + 32, label.top() + 44, label.width() - 32, 18),
                    QStringLiteral("PID %1").arg(candidate.pid));
                drawLine(QRectF(label.left(), label.top() + 62, label.width(), 18), stateText(snapshot.state));
            }
        protected:
            void hoverEnterEvent(QGraphicsSceneHoverEvent* event) override
            {
                if (auto* host = dynamic_cast<PreviewScene*>(scene())) host->highlight(this);
                if (hovered) hovered();
                QGraphicsItem::hoverEnterEvent(event);
            }
            void hoverLeaveEvent(QGraphicsSceneHoverEvent* event) override
            {
                if (auto* host = dynamic_cast<PreviewScene*>(scene()); host && host->highlighted() == this)
                    host->highlight(nullptr);
                QGraphicsItem::hoverLeaveEvent(event);
            }
            void hoverMoveEvent(QGraphicsSceneHoverEvent* event) override
            {
                if (auto* host = dynamic_cast<PreviewScene*>(scene())) host->highlight(this);
                QGraphicsItem::hoverMoveEvent(event);
            }
            void focusInEvent(QFocusEvent* event) override
            {
                if (event->reason() != Qt::MouseFocusReason)
                    if (auto* host = dynamic_cast<PreviewScene*>(scene())) host->highlight(this);
                QGraphicsItem::focusInEvent(event);
            }
            void focusOutEvent(QFocusEvent* event) override
            {
                if (auto* host = dynamic_cast<PreviewScene*>(scene()); host && host->highlighted() == this)
                    host->highlight(nullptr);
                QGraphicsItem::focusOutEvent(event);
            }
            void mousePressEvent(QGraphicsSceneMouseEvent* event) override
            { event->accept(); }
            void mouseReleaseEvent(QGraphicsSceneMouseEvent* event) override
            { if (event->button() == Qt::LeftButton && contains(event->pos()) && picked) picked(); event->accept(); }
            void keyPressEvent(QKeyEvent* event) override
            {
                if ((event->key() == Qt::Key_Return || event->key() == Qt::Key_Space) && picked) { picked(); event->accept(); }
                else QGraphicsItem::keyPressEvent(event);
            }
        private:
            QPolygonF m_polygon;
            QPolygonF m_activePolygon;
        };

        void PreviewScene::highlight(PreviewItem* item)
        {
            if (m_highlighted == item) return;
            auto* previous = m_highlighted;
            m_highlighted = item;
            if (previous) previous->update();
            if (item) item->update();
        }

        class PreviewView final : public QGraphicsView
        {
        public:
            explicit PreviewView(QWidget* parent) : QGraphicsView(parent)
            {
                setFrameShape(QFrame::NoFrame);
                setTransformationAnchor(AnchorUnderMouse);
                setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);
            }
        protected:
            void wheelEvent(QWheelEvent* event) override
            {
                if (event->modifiers().testFlag(Qt::ControlModifier))
                {
                    const qreal factor = event->angleDelta().y() > 0 ? 1.12 : 1 / 1.12;
                    const qreal next = transform().m11() * factor;
                    if (next >= .25 && next <= 3) scale(factor, factor);
                    event->accept();
                }
                else QGraphicsView::wheelEvent(event);
            }
        };

        class Chooser final : public QDialog
        {
        public:
            Chooser(WindowTargetPickerButton* owner, QPoint point, WindowTargetPickerButton::PickCallback callback)
                : QDialog(owner->window(), Qt::Window), m_owner(owner), m_callback(std::move(callback)), m_operation(new AsyncOperation(this))
            {
                setAttribute(Qt::WA_DeleteOnClose);
                setWindowFlag(Qt::WindowContextHelpButtonHint, false);
                setWindowFlag(Qt::WindowMinMaxButtonsHint, true);
                setSizeGripEnabled(true);
                setObjectName(QStringLiteral("ks_window_target_chooser"));
                StyleSecondaryWindow(this);
                ks::i18n::LanguageManager::instance().bindWindowTitle(this,
                    QStringLiteral("window.picker.title"), QStringLiteral("选择目标窗口"));
                auto* layout = new QVBoxLayout(this);
                StyleSecondaryContentLayout(layout);
                m_status = new QLabel(text("window.picker.enumerating", "正在查找此位置的窗口…"), this);
                m_status->setTextFormat(Qt::PlainText);
                m_status->setWordWrap(true);
                layout->addWidget(m_status);
                m_view = new PreviewView(this);
                m_view->viewport()->installEventFilter(this);
                m_scene = new PreviewScene(this);
                QFont previewFont = font();
                if (previewFont.pointSizeF() < 10) previewFont.setPointSizeF(10);
                m_scene->setFont(previewFont);
                m_view->setScene(m_scene);
                layout->addWidget(m_view, 1);
                auto* hint = new QLabel(text("window.picker.help", "悬停查看窗口，左键选择；滚轮滚动，Ctrl+滚轮缩放；F11 切换全屏；Esc 退出全屏或取消，右键取消。"), this);
                hint->setWordWrap(true);
                layout->addWidget(hint);
                auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
                StyleSecondaryButtonBox(buttons);
                connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
                layout->addWidget(buttons);
                // Identify the monitor in native coordinates, then use that
                // QScreen's own DIP geometry. Never divide a global origin by DPR.
                const PhysicalCoordinates coordinates;
                const HMONITOR monitor = ::MonitorFromPoint(POINT{point.x(), point.y()}, MONITOR_DEFAULTTONEAREST);
                MONITORINFOEXW info{};
                info.cbSize = sizeof(info);
                ::GetMonitorInfoW(monitor, &info);
                QScreen* screen = owner->screen();
                for (QScreen* candidate : QGuiApplication::screens())
                    if (candidate->name().compare(QString::fromWCharArray(info.szDevice), Qt::CaseInsensitive) == 0) screen = candidate;
                const QRect available = screen->availableGeometry();
                (void)winId();
                windowHandle()->setScreen(screen);
                applyResponsiveWindowGeometry(this, this, QSize(1240, 720), QSize(440, 300));
                move(available.center() - rect().center());
                BindWidgetTheme(m_view, [this] {
                    m_view->setBackgroundBrush(KswordTheme::SurfaceColor());
                    m_scene->update();
                });
                PrepareWidgetThemeBindingsForShow(this);
                const EnumerationRequest request{point, static_cast<quintptr>(winId())};
                m_operation->submit<EnumerationRequest, std::vector<Candidate>>(request, enumerate,
                    [this](const std::vector<Candidate>& values, std::uint64_t) {
                        populate(values); return true;
                    }, [this](std::exception_ptr) {
                        m_status->setText(text("window.picker.failed", "窗口查询失败，请关闭后重试。"));
                    });
            }
            ~Chooser() override { m_operation->close(); }
        protected:
            void done(int result) override { m_operation->close(); QDialog::done(result); }
            void keyPressEvent(QKeyEvent* event) override
            {
                if (event->key() == Qt::Key_F11 || (event->key() == Qt::Key_Escape && isFullScreen()))
                {
                    if (isFullScreen())
                    {
                        if (m_restoreMaximized) showMaximized();
                        else showNormal();
                    }
                    else
                    {
                        m_restoreMaximized = isMaximized();
                        showFullScreen();
                    }
                    event->accept();
                    return;
                }
                QDialog::keyPressEvent(event);
            }
            void mousePressEvent(QMouseEvent* event) override
            {
                if (event->button() == Qt::RightButton) { reject(); event->accept(); }
                else QDialog::mousePressEvent(event);
            }
            bool event(QEvent* event) override
            {
                if (event->type() == QEvent::WindowDeactivate && isVisible() && !isMinimized()) reject();
                if (event->type() == QEvent::LanguageChange)
                { m_scene->update(); if (!m_items.empty()) updateStatus(); }
                return QDialog::event(event);
            }
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (watched == m_view->viewport() && event->type() == QEvent::MouseButtonPress
                    && static_cast<QMouseEvent*>(event)->button() == Qt::RightButton)
                { reject(); return true; }
                return QDialog::eventFilter(watched, event);
            }
        private:
            void updateStatus(const Candidate* hovered = nullptr)
            {
                m_status->setText(hovered
                    ? QStringLiteral("%1  |  PID %2  |  HWND 0x%3").arg(m_status->fontMetrics().elidedText(
                        hovered->title, Qt::ElideMiddle, (std::max)(120, m_view->viewport()->width() - 320)))
                        .arg(hovered->pid).arg(hovered->hwnd, 0, 16)
                    : text("window.picker.count", "此位置有 %1 个窗口，按从上到下的 Z 序排列。").arg(m_items.size()));
            }
            void populate(const std::vector<Candidate>& candidates)
            {
                for (const auto& candidate : candidates)
                {
                    auto* item = new PreviewItem;
                    item->candidate = candidate;
                    const auto index = m_items.size();
                    item->setPos(layerPosition(index));
                    item->setZValue(-static_cast<qreal>(index));
                    item->setToolTip(Qt::convertFromPlainText(candidate.title + QLatin1Char('\n')
                        + candidate.processName + QStringLiteral("  |  PID %1").arg(candidate.pid)));
                    item->hovered = [this, item] { updateStatus(&item->candidate); };
                    item->picked = [this, item] { choose(item->candidate); };
                    m_scene->addItem(item);
                    m_items.push_back(item);
                }
                if (m_items.empty())
                {
                    m_status->setText(text("window.picker.empty", "此位置没有可预览的顶层窗口，请关闭后重新拾取。"));
                    return;
                }
                updateStatus();
                m_scene->setSceneRect(m_scene->itemsBoundingRect().adjusted(-16, -16, 16, 16));
                QTimer::singleShot(0, this, [this] {
                    const qreal zoom = (std::max)(.5, (std::min)(1., (m_view->viewport()->width() - 32.) / m_scene->sceneRect().width()));
                    m_view->scale(zoom, zoom);
                    m_view->ensureVisible(m_items.front());
                    captureNext();
                });
            }
            void captureNext()
            {
                if (m_next >= m_items.size() || !isVisible()) return;
                PreviewItem* item = m_items[m_next++];
                m_operation->submit<Candidate, Snapshot>(item->candidate, capture,
                    [this, item](const Snapshot& snapshot, std::uint64_t) {
                        item->snapshot = snapshot;
                        item->update();
                        QTimer::singleShot(0, this, [this] { captureNext(); });
                        return true;
                    }, [this, item](std::exception_ptr) {
                        item->snapshot.state = CaptureState::Unavailable;
                        item->update();
                        QTimer::singleShot(0, this, [this] { captureNext(); });
                    });
            }
            void choose(const Candidate& candidate)
            {
                if (!stillValid(candidate))
                { m_status->setText(stateText(CaptureState::Closed)); return; }
                const QPointer<WindowTargetPickerButton> owner = m_owner;
                const auto callback = m_callback;
                const auto value = candidate;
                accept();
                if (owner) QTimer::singleShot(0, owner, [owner, callback, value] {
                    if (owner && stillValid(value) && callback) callback(value.hwnd);
                });
            }
            QPointer<WindowTargetPickerButton> m_owner;
            WindowTargetPickerButton::PickCallback m_callback;
            AsyncOperation* m_operation;
            PreviewView* m_view = nullptr;
            PreviewScene* m_scene = nullptr;
            QLabel* m_status = nullptr;
            std::vector<PreviewItem*> m_items;
            std::size_t m_next = 0;
            bool m_restoreMaximized = false;
        };
    }

    WindowTargetPickerButton::WindowTargetPickerButton(QWidget* parent) : QPushButton(parent) {}
    void WindowTargetPickerButton::setPickCallback(PickCallback callback) { m_callback = std::move(callback); }

    void WindowTargetPickerButton::mousePressEvent(QMouseEvent* event)
    {
        if (event->button() == Qt::LeftButton)
        {
            const PhysicalCoordinates coordinates;
            POINT point{};
            m_tracking = ::GetCursorPos(&point) != FALSE;
            m_pressPhysical = QPoint(point.x, point.y);
            m_dragged = false;
            m_dragDistance = qRound(QApplication::startDragDistance() * devicePixelRatioF());
            if (m_tracking) grabMouse(QCursor(Qt::CrossCursor));
        }
        QPushButton::mousePressEvent(event);
    }

    void WindowTargetPickerButton::mouseMoveEvent(QMouseEvent* event)
    {
        if (m_tracking)
        {
            const PhysicalCoordinates coordinates;
            POINT point{};
            if (::GetCursorPos(&point) && (QPoint(point.x, point.y) - m_pressPhysical).manhattanLength() >= m_dragDistance)
                m_dragged = true;
        }
        QPushButton::mouseMoveEvent(event);
    }

    void WindowTargetPickerButton::mouseReleaseEvent(QMouseEvent* event)
    {
        if (event->button() != Qt::LeftButton) { QPushButton::mouseReleaseEvent(event); return; }
        POINT point{};
        bool valid = false;
        bool control = false;
        quintptr hwnd = 0;
        {
            const PhysicalCoordinates coordinates;
            // Snapshot both values before releasing capture or running Qt code.
            const bool positioned = ::GetCursorPos(&point) != FALSE;
            valid = m_tracking && positioned && (m_dragged
                || (QPoint(point.x, point.y) - m_pressPhysical).manhattanLength() >= m_dragDistance);
            control = (::GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            if (valid && !control) hwnd = reinterpret_cast<quintptr>(::WindowFromPoint(point));
        }
        if (m_tracking) releaseMouse();
        m_tracking = false;
        m_dragged = false;
        const QPointer<WindowTargetPickerButton> guard(this);
        QPushButton::mouseReleaseEvent(event);
        if (!guard || !valid || !m_callback) return;
        if (control) (new Chooser(this, QPoint(point.x, point.y), m_callback))->show();
        else m_callback(hwnd);
    }
}
