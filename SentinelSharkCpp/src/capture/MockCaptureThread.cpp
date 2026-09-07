#include "MockCaptureThread.h"
#include "../heuristics/HeuristicsEngine.h"
#include <QProcess>
#include <QHostAddress>
#include <QRandomGenerator>
#include <QThread>
#include <QTime>
#include <cstring>

namespace SS {

// ── Mock capture data ─────────────────────────────────────────────────────────

struct MockProc {
    const char* name;
    const char* dst;
    uint16_t    port;
    const char* proto;
    const char* mitre;
    Severity    sev;
    const char* info;
};

static const MockProc kMockProcs[] = {
    {"curl",          "185.220.101.5",   443, "HTTPS", "T1071.001", Severity::Critical, "Encrypted C2 beacon to Tor exit node"},
    {"python3",       "8.8.8.8",          53, "DNS",   "T1071.004", Severity::High,     "DNS tunneling attempt"},
    {"chrome",        "142.250.80.46",   443, "HTTPS", "T1567",     Severity::Medium,   "Data exfiltration to cloud storage"},
    {"ssh",           "10.0.0.1",         22, "SSH",   "T1021.004", Severity::Medium,   "SSH lateral movement"},
    {"wget",          "cdn.example.com",  80, "HTTP",  "T1105",     Severity::Medium,   "Ingress tool transfer"},
    {"powershell.exe","91.92.109.198",  4444, "TCP",   "T1059.001", Severity::Critical, "Reverse shell - non-standard port"},
    {"bash",          "192.168.1.1",    1337, "TCP",   "T1059",     Severity::Critical, "Suspicious outbound bash connection"},
    {"nginx",         "0.0.0.0",          80, "HTTP",  "",          Severity::Safe,     "Web server normal traffic"},
    {"nc",            "10.10.10.100",   9001, "TCP",   "T1095",     Severity::High,     "Netcat reverse shell attempt"},
};
static constexpr size_t kMockProcCount = sizeof(kMockProcs) / sizeof(kMockProcs[0]);

// ── MockCaptureThread implementation ─────────────────────────────────────────

MockCaptureThread::MockCaptureThread(BoundedQueue<PacketRecord, 300>* queue, QObject* parent)
    : QThread(parent), queue_(queue)
{
    setObjectName(QStringLiteral("MockCaptureThread"));
}

void MockCaptureThread::stop() {
    running_.store(false, std::memory_order_relaxed);
}

void MockCaptureThread::run() {
    running_.store(true, std::memory_order_relaxed);
    emit statusChanged(QStringLiteral("Mock capture active"));

    auto* rng = QRandomGenerator::global();

    while (running_.load(std::memory_order_relaxed)) {
        // Select a random mock process
        const size_t idx  = rng->bounded(static_cast<uint>(kMockProcCount));
        const MockProc& m = kMockProcs[idx];

        // Build src IP: 192.168.1.X
        const int lastOctet = rng->bounded(100, 121);
        const QString srcIp = QStringLiteral("192.168.1.%1").arg(lastOctet);
        const uint32_t pid  = rng->bounded(1000u, 10000u);

        PacketRecord rec;
        rec.no       = counter_.fetch_add(1, std::memory_order_relaxed) + 1;
        rec.pid      = pid;
        rec.src_port = static_cast<uint16_t>(rng->bounded(1024u, 65535u));
        rec.dst_port = m.port;
        rec.length   = static_cast<uint32_t>(rng->bounded(64u, 1500u));
        rec.severity = m.sev;

        // Get current time string HH:MM:SS.mmm
        {
            const QString ts = QTime::currentTime().toString(QStringLiteral("HH:mm:ss.zzz"));
            strncpy_s(rec.time, sizeof(rec.time), ts.toLatin1().constData(), _TRUNCATE);
        }

        strncpy_s(rec.process,  sizeof(rec.process),  m.name,   _TRUNCATE);
        strncpy_s(rec.src,      sizeof(rec.src),      srcIp.toLatin1().constData(), _TRUNCATE);
        strncpy_s(rec.dst,      sizeof(rec.dst),      m.dst,    _TRUNCATE);
        strncpy_s(rec.protocol, sizeof(rec.protocol), m.proto,  _TRUNCATE);
        strncpy_s(rec.mitre,    sizeof(rec.mitre),    m.mitre,  _TRUNCATE);
        strncpy_s(rec.info,     sizeof(rec.info),     m.info,   _TRUNCATE);

        // Drop-tail: if queue full, we simply discard — never block
        queue_->try_push(rec);

        // Sleep 14–33ms for 30–70 pkts/s
        const int sleepMs = rng->bounded(14, 34);
        QThread::msleep(static_cast<unsigned long>(sleepMs));
    }

    emit statusChanged(QStringLiteral("Mock capture stopped"));
}

} // namespace SS
