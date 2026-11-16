#include "ServiceClient.hpp"

#include <QJsonArray>
#include <QJsonDocument>

ServiceClient::ServiceClient(QString pipeName, QObject* parent) : QObject(parent), pipeName_(std::move(pipeName)) {
    reconnectTimer_.setInterval(3000);
    connect(&reconnectTimer_, &QTimer::timeout, this, &ServiceClient::tryConnect);
    connect(&socket_, &QLocalSocket::readyRead, this, &ServiceClient::onReadyRead);
    connect(&socket_, &QLocalSocket::connected, this, [this] {
        reconnectTimer_.stop();
        buffer_.clear();
        emit connectedChanged(true);
        requestStatus();
        requestEvents();
    });
    connect(&socket_, &QLocalSocket::disconnected, this, [this] {
        emit connectedChanged(false);
        reconnectTimer_.start();
    });
    connect(&socket_, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) {
        if (socket_.state() != QLocalSocket::ConnectedState && !reconnectTimer_.isActive()) reconnectTimer_.start();
    });
}

void ServiceClient::start() { tryConnect(); }

void ServiceClient::tryConnect() {
    if (socket_.state() == QLocalSocket::UnconnectedState) socket_.connectToServer(pipeName_);
}

void ServiceClient::sendCommand(const QJsonObject& cmd) {
    if (!isConnected()) {
        emit errorReceived(cmd.value("cmd").toString(), tr("Ikke tilkoblet tjenesten"));
        return;
    }
    QByteArray line = QJsonDocument(cmd).toJson(QJsonDocument::Compact);
    line.append('\n');
    socket_.write(line);
}

void ServiceClient::onReadyRead() {
    buffer_.append(socket_.readAll());
    qsizetype nl;
    while ((nl = buffer_.indexOf('\n')) >= 0) {
        const QByteArray line = buffer_.left(nl);
        buffer_.remove(0, nl + 1);
        QJsonParseError err{};
        const auto doc = QJsonDocument::fromJson(line, &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) handleMessage(doc.object());
    }
    if (buffer_.size() > kMaxLine) buffer_.clear();  // vern mot korrupt strøm
}

void ServiceClient::handleMessage(const QJsonObject& msg) {
    const QString type = msg.value("type").toString();
    if (type == "event") {
        emit eventReceived(msg.value("event").toObject());
        return;
    }
    if (type != "reply") return;
    const QString cmd = msg.value("cmd").toString();
    if (!msg.value("ok").toBool()) {
        emit errorReceived(cmd, msg.value("error").toString());
        return;
    }
    if (cmd == "get_status") emit statusReceived(msg.value("status").toObject());
    if (cmd == "get_events") {
        for (const auto& e : msg.value("events").toArray()) emit eventReceived(e.toObject());
    }
    emit replyReceived(cmd, msg);
}
