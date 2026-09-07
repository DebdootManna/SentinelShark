#pragma once
#include <QThread>
#include <QString>
#include <QStringList>
#include <atomic>
#include "../core/PacketRecord.h"
#include "../core/BoundedQueue.h"

namespace SS {

/// Enumerate available network interfaces by running "tshark -D".
/// Returns list of interface strings like "1: \\Device\\NPF_{GUID} (Ethernet)".
/// Falls back to ["1", "2", "3"] if tshark is not available.
QStringList getAvailableInterfaces(const QString& tsharkPath);

/// Translate user-friendly filter shortcuts to valid BPF syntax.
/// E.g. "http" -> "port 80", "dns" -> "port 53", "192.168.1.1" -> "host 192.168.1.1"
QString sanitizeBpfFilter(const QString& raw);

// ─────────────────────────────────────────────────────────────────────────────

/// Generates synthetic network traffic for testing without TShark or Npcap.
/// Mimics the 9 mock processes from the Python source, at 30-70 pkts/s.
class MockCaptureThread : public QThread {
    Q_OBJECT
public:
    explicit MockCaptureThread(BoundedQueue<PacketRecord, 300>* queue,
                                QObject* parent = nullptr);

    void stop();

signals:
    void statusChanged(const QString& msg);

protected:
    void run() override;

private:
    BoundedQueue<PacketRecord, 300>* queue_;
    std::atomic<bool>                running_{false};
    std::atomic<uint32_t>            counter_{0};
};

} // namespace SS
