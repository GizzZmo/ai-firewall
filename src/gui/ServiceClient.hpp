#pragma once
// Klient for named pipe-kommunikasjon med tjenesten.

#include <QJsonObject>
#include <QObject>
#include <QString>

class QLocalSocket;

class ServiceClient : public QObject {
    Q_OBJECT
public:
    explicit ServiceClient(const QString& pipeName, QObject* parent = nullptr);

    void start();
    void requestStatus();
    void requestEvents();
    void setLearningMode(bool enabled);
    void reloadRules();
    void setAiConfig(const QJsonObject& config);

signals:
    void connectedChanged(bool connected);
    void statusReceived(const QJsonObject& status);
    void eventReceived(const QJsonObject& event);
    void replyReceived(const QString& cmd, const QJsonObject& reply);
    void errorReceived(const QString& cmd, const QString& message);

private slots:
    void onReadyRead();
    void onConnected();
    void onDisconnected();

private:
    void send(const QJsonObject& msg);

    QString pipeName_;
    QLocalSocket* socket_;
    QByteArray buffer_;
};
