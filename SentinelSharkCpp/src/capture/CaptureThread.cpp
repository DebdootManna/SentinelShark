// CaptureThread.cpp  —  SS::CaptureThread
// Launches: tshark -i <iface> -T json -l [-f <bpf>]
// Reads stdout line-by-line; uses brace-counting to extract JSON objects.
// Each packet object is parsed with nlohmann::json and converted to PacketRecord.

#include "CaptureThread.h"
#include "../correlation/SocketPollThread.h"
#include "../heuristics/HeuristicsEngine.h"
#include <third_party/nlohmann/json.hpp>
#include <QProcess>
#include <QTime>
#include <QHostAddress>
#include <cstring>
#include <stdexcept>

namespace SS {

using json = nlohmann::json;

// ── Helper: safe JSON string extraction ──────────────────────────────────────

static QString jStr(const json& j, const std::string& key,
                    const QString& def = {})
{
    if (!j.is_object()) return def;
    auto it = j.find(key);
    if (it == j.end()) return def;
    if (it->is_string()) return QString::fromStdString(it->get<std::string>());
    if (it->is_array() && !it->empty() && (*it)[0].is_string())
        return QString::fromStdString((*it)[0].get<std::string>());
    return def;
}

static uint32_t jU32(const json& j, const std::string& key, uint32_t def = 0) {
    if (!j.is_object()) return def;
    auto it = j.find(key);
    if (it == j.end()) return def;
    try {
        if (it->is_string()) return static_cast<uint32_t>(std::stoul(it->get<std::string>()));
        if (it->is_number()) return it->get<uint32_t>();
    } catch (...) {}
    return def;
}

// ── Construction ──────────────────────────────────────────────────────────────

CaptureThread::CaptureThread(BoundedQueue<PacketRecord, 300>* queue,
                               const QString& tsharkPath,
                               const QString& iface,
                               const QString& bpfFilter,
                               QObject* parent)
    : QThread(parent)
    , queue_(queue)
    , tsharkPath_(tsharkPath)
    , iface_(iface)
    , bpfFilter_(bpfFilter)
{
    setObjectName(QStringLiteral("CaptureThread"));
}

void CaptureThread::stop() {
    running_.store(false, std::memory_order_relaxed);
}

// ── Thread entry point ────────────────────────────────────────────────────────

void CaptureThread::run() {
    running_.store(true, std::memory_order_relaxed);

    // Build tshark arguments
    // -T json -l : line-buffered JSON output (one object per line when used with -l)
    // -n         : disable name resolution (faster)
    // -q         : quiet (suppress summary line)
    QStringList args;
    args << "-i"  << iface_
         << "-T"  << "json"
         << "-l"
         << "-n"
         << "-q";
    if (!bpfFilter_.isEmpty())
        args << "-f" << bpfFilter_;

    QProcess proc;
    proc.setProgram(tsharkPath_);
    proc.setArguments(args);
    proc.setReadChannel(QProcess::StandardOutput);

    emit statusChanged(QStringLiteral("Starting tshark on interface %1…").arg(iface_));
    proc.start();

    if (!proc.waitForStarted(5000)) {
        emit captureError(QStringLiteral("Failed to start tshark: %1").arg(proc.errorString()));
        return;
    }
    emit statusChanged(QStringLiteral("Capturing on %1").arg(iface_));

    // tshark -T json -l outputs each packet as a standalone JSON object per line.
    // However, it may also output a JSON array [ { ... }, { ... } ].
    // We use brace counting to robustly extract complete JSON objects.
    QByteArray pending;

    while (running_.load(std::memory_order_relaxed) &&
           (proc.state() != QProcess::NotRunning || proc.canReadLine()))
    {
        // Wait up to 100ms for data
        if (!proc.waitForReadyRead(100)) continue;

        pending += proc.readAllStandardOutput();

        // Extract complete JSON objects using brace depth counting
        int depth = 0;
        int objStart = -1;

        for (int i = 0; i < pending.size(); ++i) {
            const char c = pending[i];
            if (c == '{') {
                if (depth == 0) objStart = i;
                ++depth;
            } else if (c == '}') {
                --depth;
                if (depth == 0 && objStart >= 0) {
                    // We have a complete JSON object
                    const QByteArray objData = pending.mid(objStart, i - objStart + 1);
                    objStart = -1;

                    PacketRecord rec;
                    if (parseTsharkPacket(objData, rec)) {
                        queue_->try_push(rec); // drop if full
                        const uint64_t count = packetCount_.fetch_add(1,
                                                std::memory_order_relaxed) + 1;
                        if (count % 100 == 0)
                            emit packetCountUpdated(count);
                    }
                }
            }
        }

        // Keep only unprocessed tail in pending
        if (objStart >= 0)
            pending = pending.mid(objStart);
        else if (depth == 0)
            pending.clear();
    }

    proc.terminate();
    proc.waitForFinished(3000);

    if (running_.load(std::memory_order_relaxed)) {
        // Unexpected termination
        emit captureError(QStringLiteral("tshark exited unexpectedly: %1")
                              .arg(QString::fromLocal8Bit(proc.readAllStandardError())));
    } else {
        emit statusChanged(QStringLiteral("Capture stopped"));
    }
}

// ── JSON parsing ──────────────────────────────────────────────────────────────

bool CaptureThread::parseTsharkPacket(const QByteArray& jsonData, PacketRecord& rec) {
    try {
        const json pkt = json::parse(jsonData.constData(),
                                      jsonData.constData() + jsonData.size());

        // TShark -T json structure: {"_source": {"layers": {...}}}
        if (!pkt.contains("_source")) return false;
        const json& src    = pkt["_source"];
        if (!src.contains("layers"))  return false;
        const json& layers = src["layers"];

        // ── Frame info ────────────────────────────────────────────────────────
        const json& frame  = layers.value("frame", json::object());
        const uint32_t len = jU32(frame, "frame.len");
        const QString  ts  = jStr(frame, "frame.time_relative",
                                  QTime::currentTime().toString("HH:mm:ss.zzz"));

        // ── Network layer ─────────────────────────────────────────────────────
        QString srcIp, dstIp;
        if (layers.contains("ip")) {
            const json& ip = layers["ip"];
            srcIp = jStr(ip, "ip.src");
            dstIp = jStr(ip, "ip.dst");
        } else if (layers.contains("ipv6")) {
            const json& ip6 = layers["ipv6"];
            srcIp = jStr(ip6, "ipv6.src");
            dstIp = jStr(ip6, "ipv6.dst");
        }

        // ── Transport layer ───────────────────────────────────────────────────
        uint16_t srcPort = 0, dstPort = 0;
        if (layers.contains("tcp")) {
            const json& tcp = layers["tcp"];
            srcPort = static_cast<uint16_t>(jU32(tcp, "tcp.srcport"));
            dstPort = static_cast<uint16_t>(jU32(tcp, "tcp.dstport"));
        } else if (layers.contains("udp")) {
            const json& udp = layers["udp"];
            srcPort = static_cast<uint16_t>(jU32(udp, "udp.srcport"));
            dstPort = static_cast<uint16_t>(jU32(udp, "udp.dstport"));
        }

        // ── Protocol detection (highest-layer wins) ───────────────────────────
        QString proto = "RAW";
        if (layers.contains("dns"))  proto = "DNS";
        else if (layers.contains("http")) proto = "HTTP";
        else if (layers.contains("tls") || layers.contains("ssl")) proto = "HTTPS";
        else if (layers.contains("ssh")) proto = "SSH";
        else if (layers.contains("icmp")) proto = "ICMP";
        else if (layers.contains("tcp"))  proto = "TCP";
        else if (layers.contains("udp"))  proto = "UDP";

        // Port-based fallback
        if (proto == "TCP" || proto == "UDP") {
            if (dstPort == 53 || srcPort == 53) proto = "DNS";
            else if (dstPort == 80)  proto = "HTTP";
            else if (dstPort == 443) proto = "HTTPS";
            else if (dstPort == 22)  proto = "SSH";
        }

        // ── Socket correlation (O(1), no lock) ───────────────────────────────
        const PidEntry pidEntry = SocketPollThread::instance().lookup(
                srcIp, srcPort, dstIp, dstPort);

        // ── MITRE heuristics ──────────────────────────────────────────────────
        const QStringList mitreTags = HeuristicsEngine::evaluate(
                pidEntry.processName, proto, dstPort);
        const bool lolbin = HeuristicsEngine::isLolbin(pidEntry.processName);
        const Severity sev = HeuristicsEngine::computeSeverity(0, 0, mitreTags, lolbin);

        // ── Build info string ─────────────────────────────────────────────────
        QString info;
        if (proto == "DNS" && layers.contains("dns")) {
            const json& dns = layers["dns"];
            info = QStringLiteral("DNS query: %1").arg(jStr(dns, "dns.qry.name", dstIp));
        } else if (proto == "HTTP" && layers.contains("http")) {
            const json& http = layers["http"];
            const QString method = jStr(http, "http.request.method");
            const QString uri    = jStr(http, "http.request.uri");
            info = method.isEmpty() ? QStringLiteral("HTTP %1→%2").arg(srcIp, dstIp)
                                    : QStringLiteral("%1 %2").arg(method, uri);
        } else {
            info = buildInfo(proto, srcIp, srcPort, dstIp, dstPort, len);
        }

        // ── Populate PacketRecord ─────────────────────────────────────────────
        static std::atomic<uint32_t> seqNo{0};
        rec.no       = seqNo.fetch_add(1, std::memory_order_relaxed) + 1;
        rec.pid      = pidEntry.pid;
        rec.src_port = srcPort;
        rec.dst_port = dstPort;
        rec.length   = len;
        rec.severity = sev;

        strncpy_s(rec.time,     sizeof(rec.time),    ts.toLatin1().constData(), _TRUNCATE);
        strncpy_s(rec.process,  sizeof(rec.process), pidEntry.processName.isEmpty()
                                ? "unknown" : pidEntry.processName.toLatin1().constData(), _TRUNCATE);
        strncpy_s(rec.src,      sizeof(rec.src),     srcIp.toLatin1().constData(), _TRUNCATE);
        strncpy_s(rec.dst,      sizeof(rec.dst),     dstIp.toLatin1().constData(), _TRUNCATE);
        strncpy_s(rec.protocol, sizeof(rec.protocol),proto.toLatin1().constData(), _TRUNCATE);
        {
            const QString mit = mitreTags.isEmpty() ? QString{} : mitreTags.first();
            strncpy_s(rec.mitre, sizeof(rec.mitre), mit.toLatin1().constData(), _TRUNCATE);
        }
        strncpy_s(rec.info, sizeof(rec.info), info.toLatin1().constData(), _TRUNCATE);

        return !srcIp.isEmpty();

    } catch (const std::exception&) {
        return false; // malformed JSON — skip silently
    }
}

QString CaptureThread::detectProtocol(const QByteArray& /*jsonData*/,
                                       uint16_t dstPort, uint16_t srcPort)
{
    // Port-based fallback (used before full JSON parse)
    if (dstPort == 53 || srcPort == 53) return "DNS";
    if (dstPort == 80)  return "HTTP";
    if (dstPort == 443) return "HTTPS";
    if (dstPort == 22)  return "SSH";
    if (dstPort == 3389) return "RDP";
    if (dstPort == 445)  return "SMB";
    return "TCP";
}

QString CaptureThread::buildInfo(const QString& proto, const QString& src, uint16_t srcPort,
                                  const QString& dst, uint16_t dstPort, uint32_t length)
{
    return QStringLiteral("%1 %2:%3 → %4:%5 (%6 bytes)")
        .arg(proto)
        .arg(src).arg(srcPort)
        .arg(dst).arg(dstPort)
        .arg(length);
}

} // namespace SS
