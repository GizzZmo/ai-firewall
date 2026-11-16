#include "LogWindow.hpp"

#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

#include "ServiceClient.hpp"

LogWindow::LogWindow(ServiceClient* client, QWidget* parent) : QWidget(parent), client_(client) {
    setWindowTitle(tr("AI-Firewall – logg"));
    resize(980, 600);

    status_ = new QLabel(tr("Kobler til tjenesten …"), this);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    table_ = new QTableWidget(0, 6, this);
    table_->setHorizontalHeaderLabels({tr("Tid"), tr("Type"), tr("Flyt"), tr("App"), tr("Grunn"), tr("Score")});
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->verticalHeader()->setVisible(false);

    suggestions_ = new QPlainTextEdit(this);
    suggestions_->setReadOnly(true);
    suggestions_->setPlaceholderText(tr("Foreslåtte regler fra læringsmodus vises her."));

    auto* refresh = new QPushButton(tr("Oppdater status"), this);
    auto* suggest = new QPushButton(tr("Hent regelforslag"), this);
    applyBtn_ = new QPushButton(tr("Bruk forslag …"), this);
    auto* reload = new QPushButton(tr("Last regler på nytt"), this);
    auto* clear = new QPushButton(tr("Tøm logg"), this);
    connect(refresh, &QPushButton::clicked, client_, &ServiceClient::requestStatus);
    connect(suggest, &QPushButton::clicked, client_, &ServiceClient::requestSuggestions);
    connect(reload, &QPushButton::clicked, client_, &ServiceClient::reloadRules);
    connect(clear, &QPushButton::clicked, this, [this] { table_->setRowCount(0); });
    connect(applyBtn_, &QPushButton::clicked, this, [this] {
        // Bekreftelse: forslag endrer rules.json og kan åpne for trafikk.
        if (QMessageBox::question(this, tr("Bruk regelforslag"),
                                  tr("Legge alle foreslåtte regler inn i rules.json?\nGå gjennom listen først – "
                                     "allow-regler åpner for trafikk.")) == QMessageBox::Yes)
            client_->applySuggestions();
    });

    auto* buttons = new QHBoxLayout;
    for (auto* b : {refresh, suggest, applyBtn_, reload, clear}) buttons->addWidget(b);
    buttons->addStretch();

    auto* split = new QSplitter(Qt::Vertical, this);
    split->addWidget(table_);
    split->addWidget(suggestions_);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 1);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(status_);
    layout->addLayout(buttons);
    layout->addWidget(split);

    connect(client_, &ServiceClient::replyReceived, this, [this](const QString& cmd, const QJsonObject& r) {
        if (cmd == "get_suggestions") showSuggestions(r);
        if (cmd == "apply_suggestions")
            suggestions_->appendPlainText(tr("\n%1 regler lagt til.").arg(r.value("applied").toInt()));
        if (cmd == "reload_rules") client_->requestStatus();
    });
}

void LogWindow::addEvent(const QJsonObject& ev) {
    if (table_->rowCount() >= kMaxRows) table_->removeRow(table_->rowCount() - 1);
    table_->insertRow(0);  // nyeste øverst
    const auto t = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(ev.value("time_ms").toDouble()));
    const QString type = ev.value("type").toString();
    const QStringList cols{t.toString("yyyy-MM-dd HH:mm:ss"), type, ev.value("flow").toString(),
                           ev.value("app").toString(), ev.value("reason").toString(),
                           QString::number(ev.value("score").toDouble(), 'f', 3)};
    for (int c = 0; c < cols.size(); ++c) {
        auto* item = new QTableWidgetItem(cols[c]);
        if (type == "blocked") item->setForeground(QColor(200, 30, 30));
        else if (type == "would_block") item->setForeground(QColor(190, 130, 0));
        table_->setItem(0, c, item);
    }
}

void LogWindow::updateStatus(const QJsonObject& s) {
    const auto ai = s.value("ai").toObject();
    status_->setText(tr("Læringsmodus: <b>%1</b> &nbsp; Pakker: %2 &nbsp; Blokkert: %3 &nbsp; Aktive flyter: %4 &nbsp; "
                        "Regler: %5 &nbsp; AI: %6 (%7)")
                         .arg(s.value("learning_mode").toBool() ? tr("PÅ") : tr("AV"))
                         .arg(s.value("packets").toDouble(), 0, 'f', 0)
                         .arg(s.value("blocked").toDouble(), 0, 'f', 0)
                         .arg(s.value("active_flows").toDouble(), 0, 'f', 0)
                         .arg(s.value("rules").toInt())
                         .arg(ai.isEmpty() ? tr("av") : ai.value("model").toString())
                         .arg(ai.value("healthy").toBool() ? tr("ok") : tr("FEIL – regelmotor brukes")));
}

void LogWindow::setConnected(bool connected) {
    if (!connected) status_->setText(tr("<span style='color:#b00'>Ikke tilkoblet tjenesten (kjører AiFirewall?)</span>"));
}

void LogWindow::showSuggestions(const QJsonObject& reply) {
    const auto rules = reply.value("rules").toArray();
    suggestions_->setPlainText(rules.isEmpty() ? tr("Ingen forslag ennå – la læringsmodus samle data en stund.")
                                               : QString::fromUtf8(QJsonDocument(rules).toJson(QJsonDocument::Indented)));
}

void LogWindow::showError(const QString& cmd, const QString& message) {
    if (message.contains("administrator"))
        QMessageBox::warning(this, tr("Krever administrator"),
                             tr("Kommandoen '%1' krever at GUI-et kjøres som administrator.").arg(cmd));
    else
        status_->setText(tr("<span style='color:#b00'>Feil (%1): %2</span>").arg(cmd, message.toHtmlEscaped()));
}
