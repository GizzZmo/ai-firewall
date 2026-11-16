#include "TrayApp.hpp"

#include <QAction>
#include <QApplication>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>

#include "LogWindow.hpp"
#include "ServiceClient.hpp"

TrayApp::TrayApp(const QString& pipeName, QObject* parent)
    : QObject(parent), client_(new ServiceClient(pipeName, this)), menu_(new QMenu) {
    statusAction_ = menu_->addAction(tr("Ikke tilkoblet"));
    statusAction_->setEnabled(false);
    menu_->addSeparator();
    learningAction_ = menu_->addAction(tr("Læringsmodus (ingen AI-blokkering)"));
    learningAction_->setCheckable(true);
    learningAction_->setEnabled(false);
    connect(learningAction_, &QAction::toggled, this, [this](bool on) {
        if (!updatingToggle_) client_->setLearningMode(on);
    });
    menu_->addAction(tr("Vis logg …"), this, &TrayApp::showLog);
    menu_->addAction(tr("Last regler på nytt"), client_, &ServiceClient::reloadRules);
    menu_->addSeparator();
    menu_->addAction(tr("Avslutt GUI"), qApp, &QApplication::quit);

    tray_.setContextMenu(menu_);
    connect(&tray_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::DoubleClick || r == QSystemTrayIcon::Trigger) showLog();
    });
    connect(&tray_, &QSystemTrayIcon::messageClicked, this, &TrayApp::showLog);

    connect(client_, &ServiceClient::connectedChanged, this, &TrayApp::onConnected);
    connect(client_, &ServiceClient::eventReceived, this, &TrayApp::onEvent);
    connect(client_, &ServiceClient::statusReceived, this, &TrayApp::onStatus);
    connect(client_, &ServiceClient::replyReceived, this, [this](const QString& cmd, const QJsonObject&) {
        if (cmd == "set_learning") client_->requestStatus();
    });
    connect(client_, &ServiceClient::errorReceived, this, [this](const QString& cmd, const QString& msg) {
        if (cmd == "set_learning") {
            client_->requestStatus();  // tilbakestill bryteren til faktisk tilstand
            tray_.showMessage(tr("AI-Firewall"), tr("Kunne ikke endre læringsmodus: %1").arg(msg),
                              QSystemTrayIcon::Warning, 5000);
        }
    });

    statusTimer_.setInterval(5000);
    connect(&statusTimer_, &QTimer::timeout, client_, &ServiceClient::requestStatus);
    // Varsler samles i 3 s-vinduer så en flom av blokkeringer ikke gir en flom av toasts.
    notifyTimer_.setInterval(3000);
    notifyTimer_.setSingleShot(true);
    connect(&notifyTimer_, &QTimer::timeout, this, &TrayApp::flushNotifications);

    setState(State::Disconnected);
    tray_.show();
    client_->start();
}

TrayApp::~TrayApp() {
    delete menu_;
    delete log_;
}

QIcon TrayApp::makeIcon(const QColor& color) {
    // Tegnet skjold, slik at vi ikke trenger ressursfiler.
    QPixmap pm(64, 64);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QPainterPath shield;
    shield.moveTo(32, 4);
    shield.lineTo(58, 14);
    shield.cubicTo(58, 38, 46, 52, 32, 60);
    shield.cubicTo(18, 52, 6, 38, 6, 14);
    shield.closeSubpath();
    p.fillPath(shield, color);
    p.setPen(QPen(Qt::white, 4));
    p.drawLine(20, 32, 29, 41);
    p.drawLine(29, 41, 45, 23);
    return QIcon(pm);
}

void TrayApp::setState(State s) {
    state_ = s;
    switch (s) {
        case State::Disconnected:
            tray_.setIcon(makeIcon(QColor(130, 130, 130)));
            tray_.setToolTip(tr("AI-Firewall: ikke tilkoblet tjenesten"));
            break;
        case State::Enforcing:
            tray_.setIcon(makeIcon(QColor(30, 150, 70)));
            tray_.setToolTip(tr("AI-Firewall: beskytter"));
            break;
        case State::Learning:
            tray_.setIcon(makeIcon(QColor(220, 160, 0)));
            tray_.setToolTip(tr("AI-Firewall: læringsmodus"));
            break;
        case State::AiError:
            tray_.setIcon(makeIcon(QColor(200, 40, 40)));
            tray_.setToolTip(tr("AI-Firewall: AI-feil – kun regelmotor"));
            break;
    }
}

void TrayApp::onConnected(bool connected) {
    learningAction_->setEnabled(connected);
    if (connected) {
        statusTimer_.start();
    } else {
        statusTimer_.stop();
        statusAction_->setText(tr("Ikke tilkoblet"));
        setState(State::Disconnected);
    }
}

void TrayApp::onStatus(const QJsonObject& s) {
    const bool learning = s.value("learning_mode").toBool();
    const auto ai = s.value("ai").toObject();
    const bool aiOk = ai.isEmpty() || ai.value("healthy").toBool();
    updatingToggle_ = true;
    learningAction_->setChecked(learning);
    updatingToggle_ = false;
    statusAction_->setText(tr("%1 blokkert / %2 pakker").arg(s.value("blocked").toDouble(), 0, 'f', 0)
                               .arg(s.value("packets").toDouble(), 0, 'f', 0));
    setState(!aiOk ? State::AiError : learning ? State::Learning : State::Enforcing);
    if (log_) log_->updateStatus(s);
}

void TrayApp::onEvent(const QJsonObject& ev) {
    if (log_) log_->addEvent(ev);
    const QString type = ev.value("type").toString();
    if (type == "blocked") {
        ++pendingBlocks_;
        lastBlockText_ = tr("%1\n%2").arg(ev.value("app").toString(), ev.value("flow").toString());
        if (!notifyTimer_.isActive()) notifyTimer_.start();
    } else if (type == "ai_error") {
        tray_.showMessage(tr("AI-Firewall"), tr("AI-motoren feiler – regelmotoren brukes inntil videre."),
                          QSystemTrayIcon::Warning, 5000);
    }
}

void TrayApp::flushNotifications() {
    if (pendingBlocks_ == 0) return;
    const QString text = pendingBlocks_ == 1 ? tr("Blokkerte mistenkelig trafikk:\n%1").arg(lastBlockText_)
                                             : tr("Blokkerte %1 mistenkelige forbindelser. Sist:\n%2")
                                                   .arg(pendingBlocks_)
                                                   .arg(lastBlockText_);
    tray_.showMessage(tr("AI-Firewall"), text, QSystemTrayIcon::Information, 6000);
    pendingBlocks_ = 0;
}

void TrayApp::showLog() {
    if (!log_) {
        log_ = new LogWindow(client_);
        log_->setAttribute(Qt::WA_DeleteOnClose);
        connect(client_, &ServiceClient::statusReceived, log_, &LogWindow::updateStatus);
        connect(client_, &ServiceClient::connectedChanged, log_, &LogWindow::setConnected);
        connect(client_, &ServiceClient::errorReceived, log_, &LogWindow::showError);
        client_->requestEvents();
        client_->requestStatus();
    }
    log_->show();
    log_->raise();
    log_->activateWindow();
}
