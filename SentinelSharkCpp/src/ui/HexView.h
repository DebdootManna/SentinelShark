#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QLabel>
#include <QLineEdit>
#include "../core/PacketRecord.h"

namespace SS {

/// Raw Hex & ASCII Inspector matching the Python workstation's HexView.
class HexView : public QWidget {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);

    void displayPacket(const PacketRecord& pkt);
    void clear();

private:
    void setupUi();
    static QString formatHexDump(const QByteArray& data);

    QLabel* sizeLabel_ = nullptr;
    QTextEdit* hexEdit_ = nullptr;
    QLineEdit* md5Edit_ = nullptr;
    QLineEdit* sha256Edit_ = nullptr;
};

} // namespace SS
