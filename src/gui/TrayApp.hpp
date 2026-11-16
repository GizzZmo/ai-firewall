// System tray-ikon med meny, varsler og læringsmodus-bryter.
#pragma once

#include <QElapsedTimer>
#include <QIcon>
#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QSystemTrayIcon>
#include <QTimer>

class QAction;
class QMenu;
class LogWindow;
class ServiceClient;

class TrayApp : public QObject {
    Q_OBJECT
public:
    explicit TrayApp(const QString& pipeName, QObject* parent = nullptr);
    ~TrayApp() override;

private slots:
    void onEvent(const QJsonObject& ev);
    void onStatus(const QJsonObject& status);
    void onConnected(bool connected);
    void flushNotifications();
    void showLog();

private:
    enum class State { Disconnected, Enforcing, Learning, AiError };
    void setState(State s);
    static QIcon makeIcon(const QColor& color);

    ServiceClient* client_;
    QSystemTrayIcon tray_;
    QMenu* menu_;
    QAction* statusAction_;
    QAction* learningAction_;
    QPointer<LogWindow> log_;
    QTimer statusTimer_;
    QTimer notifyTimer_;
    int pendingBlocks_{0};
    QString lastBlockText_;
    State state_{State::Disconnected};
    bool updatingToggle_{false};
};
