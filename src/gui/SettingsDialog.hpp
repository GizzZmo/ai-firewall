#pragma once
// Innstillingsdialog for AI-konfigurasjon.

#include <QDialog>
#include <QJsonObject>

class QLineEdit;
class QComboBox;
class QCheckBox;
class QSpinBox;
class QDoubleSpinBox;
class ServiceClient;

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(ServiceClient* client, QWidget* parent = nullptr);

private slots:
    void onSave();
    void onProviderChanged(int index);
    void onStatusReceived(const QJsonObject& status);

private:
    void loadCurrentSettings();
    void updateUiForProvider();

    ServiceClient* client_;

    QCheckBox* enabledCheck_;
    QComboBox* providerCombo_;
    QLineEdit* apiKeyEdit_;
    QLineEdit* endpointEdit_;
    QLineEdit* modelEdit_;
    QLineEdit* localModelEdit_;
    QDoubleSpinBox* blockThreshold_;
    QDoubleSpinBox* allowThreshold_;
    QSpinBox* timeoutSpin_;
};
