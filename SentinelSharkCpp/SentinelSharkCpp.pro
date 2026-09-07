QT += core gui widgets network

CONFIG += c++17
CONFIG += windows

TARGET = SentinelShark
TEMPLATE = app

INCLUDEPATH += \
    src \
    . \
    third_party

HEADERS += \
    src/core/PacketRecord.h \
    src/core/RingBuffer.h \
    src/core/BoundedQueue.h \
    src/config/AppConfig.h \
    src/correlation/ProcessNameCache.h \
    src/correlation/SocketPollThread.h \
    src/heuristics/HeuristicsEngine.h \
    src/capture/InterfaceScanner.h \
    src/capture/MockCaptureThread.h \
    src/capture/CaptureThread.h \
    src/model/PacketTableModel.h \
    src/model/SeverityDelegate.h \
    src/threatintel/ThreatIntelWorker.h \
    src/udm/UdmNormalizer.h \
    src/response/ResponseEngine.h \
    src/ui/AnalyticsSidebar.h \
    src/ui/DetectionDetailPanel.h \
    src/ui/InspectionPanel.h \
    src/ui/SettingsDialog.h \
    src/ui/MainWindow.h

SOURCES += \
    src/main.cpp \
    src/config/AppConfig.cpp \
    src/correlation/ProcessNameCache.cpp \
    src/correlation/SocketPollThread.cpp \
    src/heuristics/HeuristicsEngine.cpp \
    src/capture/InterfaceScanner.cpp \
    src/capture/MockCaptureThread.cpp \
    src/capture/CaptureThread.cpp \
    src/model/PacketTableModel.cpp \
    src/model/SeverityDelegate.cpp \
    src/threatintel/ThreatIntelWorker.cpp \
    src/udm/UdmNormalizer.cpp \
    src/response/ResponseEngine.cpp \
    src/ui/AnalyticsSidebar.cpp \
    src/ui/DetectionDetailPanel.cpp \
    src/ui/InspectionPanel.cpp \
    src/ui/SettingsDialog.cpp \
    src/ui/MainWindow.cpp

RESOURCES += \
    resources/resources.qrc

RC_FILE = resources/SentinelShark.rc

win32 {
    LIBS += -liphlpapi -lpsapi -ladvapi32 -lws2_32 -ldwmapi
    QMAKE_CXXFLAGS += /utf-8 /W4
}
