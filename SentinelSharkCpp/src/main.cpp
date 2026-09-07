#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QIcon>
#include <QFile>
#include "ui/MainWindow.h"
#include "config/AppConfig.h"

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#endif

int main(int argc, char *argv[]) {
    // Enable High DPI scaling
    QApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    QApplication app(argc, argv);
    app.setApplicationName("SentinelShark");
    app.setApplicationVersion("2.0.0");
    app.setOrganizationName("SentinelShark");

    // Command line parser
    QCommandLineParser parser;
    parser.setApplicationDescription("SentinelShark — Host-Aware EDR & Network Analysis Platform");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption mockOption(QStringList() << "m" << "mock", "Run in mock traffic generation mode");
    parser.addOption(mockOption);

    QCommandLineOption ifaceOption(QStringList() << "i" << "interface", "Capture interface name or index", "interface");
    parser.addOption(ifaceOption);

    QCommandLineOption bpfOption(QStringList() << "f" << "filter", "BPF capture filter string", "filter");
    parser.addOption(bpfOption);

    parser.process(app);

    // Apply CLI overrides to AppConfig
    auto& cfg = SS::AppConfig::instance();
    if (parser.isSet(mockOption)) {
        cfg.mockMode = true;
    }
    if (parser.isSet(ifaceOption)) {
        cfg.defaultInterface = parser.value(ifaceOption);
    }
    if (parser.isSet(bpfOption)) {
        cfg.bpfFilter = parser.value(bpfOption);
    }

    // Default font: Segoe UI or Inter
    QFont defaultFont("Segoe UI", 9);
    defaultFont.setStyleHint(QFont::SansSerif);
    app.setFont(defaultFont);

    // Load global QSS style sheet
    QFile styleFile(":/style.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        app.setStyleSheet(QString::fromUtf8(styleFile.readAll()));
        styleFile.close();
    }

    SS::MainWindow mainWindow;

#ifdef Q_OS_WIN
    // Enable Windows 11 / 10 Dark Mode Titlebar
    HWND hwnd = reinterpret_cast<HWND>(mainWindow.winId());
    BOOL darkMode = TRUE;
    // DWMWA_USE_IMMERSIVE_DARK_MODE (20 on Windows 10 build 19041+ / Windows 11)
    DwmSetWindowAttribute(hwnd, 20, &darkMode, sizeof(darkMode));
#endif

    mainWindow.show();

    return app.exec();
}
