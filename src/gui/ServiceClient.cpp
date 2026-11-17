#include "ServiceClient.hpp"

#include <QJsonDocument>
#include <QLocalSocket>

ServiceClient::ServiceClient(const QString& pipeName, QObject* parent)
    : QObject(parent), pipeName_(pipeName), socket_(new QLocalSocket(this)) {
    connect(socket_, &QLocalSocket::readyRead, this, &ServiceClient::onReadyRead);
    connect(socket_, &QLocalSocket::connected, this, &ServiceClient::onConnected);
    connect(socket_, &QLocalSocket::disconnected, this, &ServiceClient::onDisconnected);
}

void ServiceClient::start() {
    socket_->connectToServer("\\\\.\\pipe\\" + pipeName_);
}

void ServiceClient::send(const QJsonObject& msg) {
    if (socket_->state() != QLocalSocket::ConnectedState) return;
    QJsonDocument doc(msg);
    socket_->write(doc.toJson(QJsonDocument::Compact) + "\n");
}

void ServiceClient::requestStatus() {
    send({{"cmd", "get_status"}});
}

void ServiceClient::requestEvents() {
    send({{"cmd", "get_events"}});
}

void ServiceClient::setLearningMode(bool enabled) {
    send({{"cmd", "set_learning"}, {"enabled", enabled}});
}

void ServiceClient::reloadRules() {
    send({{"cmd", "reload_rules"}});
}

void ServiceClient::setAiConfig(const QJsonObject& config) {
    QJsonObject msg;
    msg["cmd"] = "set_ai_config";
    msg["config"] = config;
    send(msg);
}

void ServiceClient::onReadyRead() {
    buffer_.append(socket_->readAll());
    while (true) {
        int idx = buffer_.indexOf('\n');
        if (idx < 0) break;
        QByteArray line = buffer_.left(idx);
        buffer_.remove(0, idx + 1);

        QJsonDocument doc = QJsonDocument::fromJson(line);
        if (!doc.isObject()) continue;
        QJsonObject obj = doc.object();

        const QString type = obj.value("type").toString();
        if (type == "event") {
            emit eventReceived(obj.value("event").toObject());
        } else if (type == "reply") {
            const QString cmd = obj.value("cmd").toString();
            if (obj.value("ok").toBool()) {
                if (cmd == "get_status") {
                    emit statusReceived(obj);
                }
                emit replyReceived(cmd, obj);
            } else {
                emit errorReceived(cmd, obj.value("message").toString());
            }
        }
    }
}

void ServiceClient::onConnected() {
    emit connectedChanged(true);
}

void ServiceClient::onDisconnected() {
    emit connectedChanged(false);
    // Prøv å koble til igjen etter 2 sekunder
    QTimer::singleShot(2000, this, &ServiceClient::start);
}
