// Vindu med hendelseslogg, status og læringsforslag.
#pragma once

#include <QJsonObject>
#include <QWidget>

class QLabel;
class QTableWidget;
class QPlainTextEdit;
class QPushButton;
class ServiceClient;

class LogWindow : public QWidget {
    Q_OBJECT
public:
    explicit LogWindow(ServiceClient* client, QWidget* parent = nullptr);

public slots:
    void addEvent(const QJsonObject& ev);
    void updateStatus(const QJsonObject& status);
    void setConnected(bool connected);
    void showSuggestions(const QJsonObject& reply);
    void showError(const QString& cmd, const QString& message);

private:
    static constexpr int kMaxRows = 2000;
    ServiceClient* client_;
    QLabel* status_;
    QTableWidget* table_;
    QPlainTextEdit* suggestions_;
    QPushButton* applyBtn_;
};
