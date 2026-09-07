cmake_minimum_required(VERSION 3.20)

project(SentinelShark VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt Automated Tools
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 Packages
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# Sources
set(SOURCES
    # Entry point
    src/main.cpp

    # Core data structures
    src/core/PacketRecord.h
    src/core/RingBuffer.h
    src/core/BoundedQueue.h

    # Configuration
    src/config/AppConfig.h
    src/config/AppConfig.cpp

    # Socket & Process correlation
    src/correlation/ProcessNameCache.h
    src/correlation/ProcessNameCache.cpp
    src/correlation/SocketPollThread.h
    src/correlation/SocketPollThread.cpp

    # Heuristics & Behavioral engine
    src/heuristics/HeuristicsEngine.h
    src/heuristics/HeuristicsEngine.cpp

    # Capture engines
    src/capture/InterfaceScanner.h
    src/capture/InterfaceScanner.cpp
    src/capture/MockCaptureThread.h
    src/capture/MockCaptureThread.cpp
    src/capture/CaptureThread.h
    src/capture/CaptureThread.cpp

    # Model / View
    src/model/PacketTableModel.h
    src/model/PacketTableModel.cpp
    src/model/SeverityDelegate.h
    src/model/SeverityDelegate.cpp

    # Threat Intelligence & UDM
    src/threatintel/ThreatIntelWorker.h
    src/threatintel/ThreatIntelWorker.cpp
    src/udm/UdmNormalizer.h
    src/udm/UdmNormalizer.cpp

    # Active Response Engine
    src/response/ResponseEngine.h
    src/response/ResponseEngine.cpp

    # UI Components
    src/ui/AnalyticsSidebar.h
    src/ui/AnalyticsSidebar.cpp
    src/ui/DetectionDetailPanel.h
    src/ui/DetectionDetailPanel.cpp
    src/ui/InspectionPanel.h
    src/ui/InspectionPanel.cpp
    src/ui/SettingsDialog.h
    src/ui/SettingsDialog.cpp
    src/ui/InterfaceSelectionDialog.h
    src/ui/InterfaceSelectionDialog.cpp
    src/ui/MainWindow.h
    src/ui/MainWindow.cpp

    # Resources
    resources/resources.qrc
    resources/SentinelShark.rc
)

# Executable definition
add_executable(SentinelShark WIN32 ${SOURCES})

# Target Include Directories
target_include_directories(SentinelShark PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/resources
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# Target Link Libraries
target_link_libraries(SentinelShark PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    iphlpapi
    psapi
    advapi32
    ws2_32
    dwmapi
)

# MSVC specific optimization and warnings
if(MSVC)
    target_compile_options(SentinelShark PRIVATE
        /W4
        /utf-8
        /permissive-
        $<$<CONFIG:Release>:/O2 /Oi /Gy>
    )
    target_link_options(SentinelShark PRIVATE
        $<$<CONFIG:Release>:/OPT:REF /OPT:ICF>
    )
endif()

# Installation rules
install(TARGETS SentinelShark
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)
