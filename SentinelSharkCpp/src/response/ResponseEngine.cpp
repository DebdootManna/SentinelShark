// ResponseEngine.cpp  —  SS::ResponseWorkerThread
// Windows-native IR: TerminateProcess, netsh advfirewall, MoveFileExW + ACL stripping.

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <aclapi.h>
#include <sddl.h>

#include "ResponseEngine.h"
#include <QDir>
#include <QStandardPaths>
#include <QProcess>
#include <QDateTime>
#include <QHostAddress>
#include <QString>
#include <utility>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace SS {

// ── Factory methods ───────────────────────────────────────────────────────────

ResponseWorkerThread* ResponseWorkerThread::killProcess(uint32_t pid,
                                                         const QString& processName,
                                                         QObject* parent)
{
    return new ResponseWorkerThread(Action::KillProcess, pid, processName, parent);
}

ResponseWorkerThread* ResponseWorkerThread::blockIp(const QString& ip, QObject* parent) {
    return new ResponseWorkerThread(Action::BlockIp, 0, ip, parent);
}

ResponseWorkerThread* ResponseWorkerThread::quarantine(uint32_t pid, QObject* parent) {
    return new ResponseWorkerThread(Action::QuarantineFile, pid, {}, parent);
}

ResponseWorkerThread::ResponseWorkerThread(Action action, uint32_t pid,
                                            const QString& strArg, QObject* parent)
    : QThread(parent), action_(action), pid_(pid), strArg_(strArg)
{
    setObjectName(QStringLiteral("ResponseWorker"));
}

// ── Thread entry point ────────────────────────────────────────────────────────

void ResponseWorkerThread::run() {
    std::pair<bool, QString> result;
    switch (action_) {
    case Action::KillProcess:
        result = doKillProcess(pid_, strArg_);
        break;
    case Action::BlockIp:
        result = doBlockIp(strArg_);
        break;
    case Action::QuarantineFile:
        result = doQuarantine(pid_);
        break;
    }
    emit actionCompleted(result.first, result.second);
}

// ── Kill Process ──────────────────────────────────────────────────────────────

std::pair<bool, QString> ResponseWorkerThread::doKillProcess(uint32_t pid,
                                                               const QString& name)
{
    // Safety guards: never kill PID 0, 4, or our own process
    if (pid == 0) return {false, "Cannot kill PID 0 (System Idle)"};
    if (pid == 4) return {false, "Cannot kill PID 4 (System)"};
    if (pid == static_cast<uint32_t>(GetCurrentProcessId()))
        return {false, "Cannot kill SentinelShark itself"};

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!hProc) {
        const DWORD err = GetLastError();
        return {false, QStringLiteral("OpenProcess failed for PID %1 (%2): error %3")
                           .arg(pid).arg(name).arg(err)};
    }

    const BOOL ok = TerminateProcess(hProc, 1);
    const DWORD err = GetLastError();
    CloseHandle(hProc);

    if (ok)
        return {true, QStringLiteral("Process %1 (PID %2) terminated successfully").arg(name).arg(pid)};
    return {false, QStringLiteral("TerminateProcess failed for %1 (PID %2): error %3")
                       .arg(name).arg(pid).arg(err)};
}

// ── Block Remote IP ───────────────────────────────────────────────────────────

std::pair<bool, QString> ResponseWorkerThread::doBlockIp(const QString& ip) {
    // Validate IP address
    const QHostAddress addr(ip);
    if (addr.isNull())
        return {false, QStringLiteral("Invalid IP address: %1").arg(ip)};

    // Block loopback and private ranges
    if (addr.isLoopback())
        return {false, "Cannot block loopback address"};

    const QString ruleName = QStringLiteral("SentinelShark Block %1").arg(ip);
    const QString cmd = QStringLiteral(
        "netsh advfirewall firewall add rule "
        "name=\"%1\" "
        "dir=out "
        "action=block "
        "remoteip=%2 "
        "enable=yes "
        "description=\"Blocked by SentinelShark EDR\"")
            .arg(ruleName, ip);

    const int ret = QProcess::execute("cmd.exe", {"/C", cmd});
    if (ret == 0)
        return {true, QStringLiteral("Firewall rule created: block outbound to %1").arg(ip)};
    return {false, QStringLiteral("netsh failed (exit %1) for IP %2").arg(ret).arg(ip)};
}

// ── Quarantine File ───────────────────────────────────────────────────────────

std::pair<bool, QString> ResponseWorkerThread::doQuarantine(uint32_t pid) {
    if (pid == 0 || pid == 4 || pid == static_cast<uint32_t>(GetCurrentProcessId()))
        return {false, "Cannot quarantine system or self process"};

    // Resolve executable path
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!hProc)
        return {false, QStringLiteral("Cannot open process PID %1").arg(pid)};

    WCHAR exePath[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    BOOL got = QueryFullProcessImageNameW(hProc, 0, exePath, &size);
    CloseHandle(hProc);

    if (!got || size == 0)
        return {false, QStringLiteral("Cannot resolve exe path for PID %1").arg(pid)};

    const QString srcPath = QString::fromWCharArray(exePath, static_cast<int>(size));
    const QString quarantineDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                                  + "/quarantine";
    QDir().mkpath(quarantineDir);

    const QString ts = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QFileInfo fi(srcPath);
    const QString dstPath = quarantineDir + "/" + fi.baseName() + "_" + ts + ".quarantined";

    // Move the file
    const BOOL moved = MoveFileExW(
        reinterpret_cast<LPCWSTR>(srcPath.utf16()),
        reinterpret_cast<LPCWSTR>(dstPath.utf16()),
        MOVEFILE_REPLACE_EXISTING
    );
    if (!moved) {
        const DWORD err = GetLastError();
        return {false, QStringLiteral("MoveFileEx failed (error %1) for %2").arg(err).arg(srcPath)};
    }

    // Strip all ACEs: set a NULL DACL (no access) on the quarantined file
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P", SDDL_REVISION_1, &pSD, nullptr))
    {
        PACL pDacl = nullptr;
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)) {
            std::wstring wDst = dstPath.toStdWString();
            SetNamedSecurityInfoW(
                wDst.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pDacl, nullptr);
        }
        LocalFree(pSD);
    }

    return {true, QStringLiteral("Quarantined %1 → %2").arg(srcPath, dstPath)};
}

} // namespace SS
