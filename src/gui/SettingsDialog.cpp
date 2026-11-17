#include "SettingsDialog.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include "ServiceClient.hpp"

SettingsDialog::SettingsDialog(ServiceClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(tr("AI-innstillinger"));
    setMinimumWidth(450);

    auto* layout = new QVBoxLayout(this);

    enabledCheck_ = new QCheckBox(tr("Aktiver AI-beslutninger"));
    layout->addWidget(enabledCheck_);

    auto* providerGroup = new QGroupBox(tr("AI-leverandør"));
    auto* providerLayout = new QFormLayout(providerGroup);

    providerCombo_ = new QComboBox;
    providerCombo_->addItem(tr("Lokal ONNX-modell"), "local");
    providerCombo_->addItem(tr("OpenAI API"), "openai");
    providerCombo_->addItem(tr("Azure OpenAI"), "azure");
    providerCombo_->addItem(tr("Google Gemini"), "gemini");
    providerCombo_->addItem(tr("xAI Grok"), "grok");
    providerCombo_->addItem(tr("Egendefinert endpoint"), "custom");
    connect(providerCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SettingsDialog::onProviderChanged);
    providerLayout->addRow(tr("Type:"), providerCombo_);

    localModelEdit_ = new QLineEdit;
    localModelEdit_->setPlaceholderText("models/flow_classifier.onnx");
    providerLayout->addRow(tr("Modellfil:"), localModelEdit_);

    apiKeyEdit_ = new QLineEdit;
    apiKeyEdit_->setEchoMode(QLineEdit::Password);
    apiKeyEdit_->setPlaceholderText(tr("API-nøkkel"));
    providerLayout->addRow(tr("API-nøkkel:"), apiKeyEdit_);

    endpointEdit_ = new QLineEdit;
    endpointEdit_->setPlaceholderText("https://...");
    providerLayout->addRow(tr("Endpoint:"), endpointEdit_);

    modelEdit_ = new QLineEdit;
    modelEdit_->setPlaceholderText("modellnavn");
    providerLayout->addRow(tr("Modellnavn:"), modelEdit_);

    timeoutSpin_ = new QSpinBox;
    timeoutSpin_->setRange(1000, 30000);
    timeoutSpin_->setValue(5000);
    timeoutSpin_->setSuffix(" ms");
    providerLayout->addRow(tr("Timeout:"), timeoutSpin_);

    layout->addWidget(providerGroup);

    auto* thresholdGroup = new QGroupBox(tr("Beslutningsterskler"));
    auto* thresholdLayout = new QFormLayout(thresholdGroup);

    blockThreshold_ = new QDoubleSpinBox;
    blockThreshold_->setRange(0.0, 1.0);
    blockThreshold_->setSingleStep(0.05);
    blockThreshold_->setValue(0.90);
    thresholdLayout->addRow(tr("Blokker ved score ≥:"), blockThreshold_);

    allowThreshold_ = new QDoubleSpinBox;
    allowThreshold_->setRange(0.0, 1.0);
    allowThreshold_->setSingleStep(0.05);
    allowThreshold_->setValue(0.30);
    thresholdLayout->addRow(tr("Tillat ved score ≤:"), allowThreshold_);

    layout->addWidget(thresholdGroup);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::onSave);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    connect(client_, &ServiceClient::statusReceived, this, &SettingsDialog::onStatusReceived);
    client_->requestStatus();

    updateUiForProvider();
}

void SettingsDialog::onProviderChanged(int) {
    updateUiForProvider();
}

void SettingsDialog::updateUiForProvider() {
    const QString type = providerCombo_->currentData().toString();
    const bool isLocal = (type == "local");

    localModelEdit_->setVisible(isLocal);
    // Finn label-widgeten (raden før)
    auto* form = qobject_cast<QFormLayout*>(localModelEdit_->parentWidget()->layout());
    if (form) {
        auto* label = form->labelForField(localModelEdit_);
        if (label) label->setVisible(isLocal);
    }

    apiKeyEdit_->setVisible(!isLocal);
    endpointEdit_->setVisible(!isLocal);
    modelEdit_->setVisible(!isLocal);
    timeoutSpin_->setVisible(!isLocal);

    // Sett placeholder og standardverdier basert på leverandør
    if (type == "openai") {
        endpointEdit_->setPlaceholderText("https://api.openai.com/v1/chat/completions");
        modelEdit_->setPlaceholderText("gpt-4o-mini");
        apiKeyEdit_->setPlaceholderText("sk-...");
    } else if (type == "azure") {
        endpointEdit_->setPlaceholderText("https://<resource>.openai.azure.com/...");
        modelEdit_->setPlaceholderText("gpt-4o");
        apiKeyEdit_->setPlaceholderText("Azure API-nøkkel");
    } else if (type == "gemini") {
        endpointEdit_->setPlaceholderText("https://generativelanguage.googleapis.com/v1beta/models");
        modelEdit_->setPlaceholderText("gemini-2.0-flash");
        apiKeyEdit_->setPlaceholderText("AIza...");
    } else if (type == "grok") {
        endpointEdit_->setPlaceholderText("https://api.x.ai/v1/chat/completions");
        modelEdit_->setPlaceholderText("grok-3");
        apiKeyEdit_->setPlaceholderText("xai-...");
    } else if (type == "custom") {
        endpointEdit_->setPlaceholderText("https://din-endpoint/v1/chat/completions");
        modelEdit_->setPlaceholderText("modellnavn");
        apiKeyEdit_->setPlaceholderText("API-nøkkel");
    }
}

void SettingsDialog::onStatusReceived(const QJsonObject& status) {
    const auto ai = status.value("ai_config").toObject();
    if (ai.isEmpty()) return;

    enabledCheck_->setChecked(ai.value("enabled").toBool(true));

    const QString provider = ai.value("provider").toString("local");
    int idx = providerCombo_->findData(provider);
    if (idx >= 0) providerCombo_->setCurrentIndex(idx);

    localModelEdit_->setText(ai.value("model_path").toString());
    if (ai.value("has_api_key").toBool()) {
        apiKeyEdit_->setPlaceholderText(tr("(nøkkel er satt)"));
    }
    endpointEdit_->setText(ai.value("endpoint").toString());
    modelEdit_->setText(ai.value("model_name").toString());
    timeoutSpin_->setValue(ai.value("timeout_ms").toInt(5000));
    blockThreshold_->setValue(ai.value("block_threshold").toDouble(0.90));
    allowThreshold_->setValue(ai.value("allow_threshold").toDouble(0.30));
}

void SettingsDialog::onSave() {
    QJsonObject config;
    config["enabled"] = enabledCheck_->isChecked();
    config["provider"] = providerCombo_->currentData().toString();
    config["model_path"] = localModelEdit_->text();

    if (!apiKeyEdit_->text().isEmpty()) {
        config["api_key"] = apiKeyEdit_->text();
    }
    config["endpoint"] = endpointEdit_->text();
    config["model_name"] = modelEdit_->text();
    config["timeout_ms"] = timeoutSpin_->value();
    config["block_threshold"] = blockThreshold_->value();
    config["allow_threshold"] = allowThreshold_->value();

    client_->setAiConfig(config);
    accept();
}
