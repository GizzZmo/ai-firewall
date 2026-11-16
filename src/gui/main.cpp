// aifw_gui – system tray-app for AI-Firewall. Kjører som vanlig bruker; kommandoer som
// endrer tilstand (læringsmodus, regler) krever at GUI-et startes som administrator.
//
//   aifw_gui.exe [--pipe aifw]
#include <QApplication>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QSystemTrayIcon>

#include "TrayApp.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("AI-Firewall");
    QApplication::setOrganizationName("AI-Firewall");
    QApplication::setQuitOnLastWindowClosed(false);  // lever i system tray

    QCommandLineParser parser;
    parser.setApplicationDescription("AI-Firewall system tray");
    parser.addHelpOption();
    QCommandLineOption pipeOpt("pipe", "Navn på named pipe (standard: aifw)", "name", "aifw");
    parser.addOption(pipeOpt);
    parser.process(app);

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        QMessageBox::critical(nullptr, "AI-Firewall", "Fant ingen system tray på denne maskinen.");
        return 1;
    }
    TrayApp tray(parser.value(pipeOpt));
    return QApplication::exec();
}
