#pragma once
#include <QThread>
#include <QString>
#include <atomic>
#include <cstdint>
#include "../core/PacketRecord.h"
#include "../core/BoundedQueue.h"

namespace SS {

/// Launches tshark via QProcess and streams TShark JSON output.
/// Parses each packet JSON object and pushes a PacketRecord to the bounded queue.
/// Uses drop-tail: if the queue is full, the packet is silently discarded.
class CaptureThread : public QThread {
    Q_OBJECT
public:
    explicit CaptureThread(BoundedQueue<PacketRecord, 300>* queue,
                           const QString& tsharkPath,
                           const QString& iface,
                           const QString& bpfFilter,
                           QObject* parent = nullptr);

    void stop();

    uint64_t packetCount() const noexcept {
        return packetCount_.load(std::memory_order_relaxed);
    }

signals:
    void statusChanged(const QString& msg);
    void captureError(const QString& msg);
    void packetCountUpdated(uint64_t count);

protected:
    void run() override;

private:
    /// Parse one JSON object from tshark's -T json output.
    /// Returns true and populates rec if successful.
    bool parseTsharkPacket(const QByteArray& jsonData, PacketRecord& rec);

    /// Determine protocol string from the layers JSON keys.
    static QString detectProtocol(const QByteArray& jsonData,
                                  uint16_t dstPort, uint16_t srcPort);

    /// Build a human-readable info string from packet fields.
    static QString buildInfo(const QString& proto, const QString& src, uint16_t srcPort,
                              const QString& dst, uint16_t dstPort, uint32_t length);

    BoundedQueue<PacketRecord, 300>* queue_;
    QString                          tsharkPath_;
    QString                          iface_;
    QString                          bpfFilter_;
    std::atomic<bool>                running_{false};
    std::atomic<uint64_t>            packetCount_{0};
};

} // namespace SS
