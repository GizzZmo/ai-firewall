// Klient mot tjenestens named pipe. QLocalSocket bruker \\.\pipe\<navn> på Windows
// (og Unix-socket på andre plattformer), så klassen er portabel.
#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QLocalSocket>
#include <QObject>
#include <QTimer>

class ServiceClient : public QObject {
    Q_OBJECT
public:
    explicit ServiceClient(QString pipeName, QObject* parent = nullptr);

    void start();
    [[nodiscard]] bool isConnected() const { return socket_.state() == QLocalSocket::ConnectedState; }

public slots:
    void sendCommand(const QJsonObject& cmd);
    void requestStatus() { sendCommand({{"cmd", "get_status"}}); }
    void setLearningMode(bool on) { sendCommand({{"cmd", "set_learning"}, {"enabled", on}}); }
    void reloadRules() { sendCommand({{"cmd", "reload_rules"}}); }
    void requestSuggestions() { sendCommand({{"cmd", "get_suggestions"}}); }
    void applySuggestions() { sendCommand({{"cmd", "apply_suggestions"}}); }
    void requestEvents() { sendCommand({{"cmd", "get_events"}}); }

signals:
    void connectedChanged(bool connected);
    void eventReceived(const QJsonObject& event);
    void statusReceived(const QJsonObject& status);
    void replyReceived(const QString& cmd, const QJsonObject& reply);
    void errorReceived(const QString& cmd, const QString& message);

private slots:
    void onReadyRead();
    void tryConnect();

private:
    void handleMessage(const QJsonObject& msg);

    static constexpr int kMaxLine = 64 * 1024;
    QString pipeName_;
    QLocalSocket socket_;
    QTimer reconnectTimer_;
    QByteArray buffer_;
};
