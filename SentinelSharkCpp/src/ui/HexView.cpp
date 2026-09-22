#include "HexView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QCryptographicHash>
#include <QFont>
#include <QFontInfo>

namespace SS {

HexView::HexView(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void HexView::setupUi() {
    setObjectName("HexView");
    setStyleSheet("QWidget#HexView { background-color: #0D1117; }");

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(6, 6, 6, 6);
    layout->setSpacing(6);

    // Header bar
    auto* topBar = new QHBoxLayout();
    topBar->setContentsMargins(4, 2, 4, 2);

    auto* titleLbl = new QLabel("Raw Packet Bytes", this);
    titleLbl->setStyleSheet("font-weight: 700; color: #22D3EE; font-size: 12px; font-family: 'JetBrains Mono', Consolas, monospace;");

    auto* subLbl = new QLabel("Hex / ASCII", this);
    subLbl->setStyleSheet("color: #94A3B8; font-size: 11px; font-family: 'JetBrains Mono', Consolas, monospace;");

    sizeLabel_ = new QLabel("", this);
    sizeLabel_->setStyleSheet("color: #94A3B8; font-size: 11px; font-family: 'JetBrains Mono', Consolas, monospace;");

    topBar->addWidget(titleLbl);
    topBar->addWidget(subLbl);
    topBar->addStretch();
    topBar->addWidget(sizeLabel_);
    layout->addLayout(topBar);

    // Hex Text Editor
    hexEdit_ = new QTextEdit(this);
    hexEdit_->setReadOnly(true);
    hexEdit_->setLineWrapMode(QTextEdit::NoWrap);

    QFont monoFont("JetBrains Mono", 10);
    if (!QFontInfo(monoFont).exactMatch()) {
        monoFont.setFamily("Consolas");
    }
    hexEdit_->setFont(monoFont);
    hexEdit_->setStyleSheet(R"(
        QTextEdit {
            background-color: #000810;
            color: #22D3EE;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 11px;
            border: 1px solid #1E293B;
            padding: 8px;
        }
    )");
    layout->addWidget(hexEdit_, 1);

    // Hash Chips Bar
    auto* hashBar = new QHBoxLayout();
    hashBar->setContentsMargins(2, 2, 2, 2);
    hashBar->setSpacing(6);

    auto* lblMd5 = new QLabel("MD5:", this);
    lblMd5->setStyleSheet("color: #22D3EE; font-weight: 600; font-family: monospace; font-size: 10px;");

    md5Edit_ = new QLineEdit(this);
    md5Edit_->setReadOnly(true);
    md5Edit_->setStyleSheet(R"(
        QLineEdit {
            background-color: #0A1520;
            color: #94A3B8;
            border: 1px solid #1A2535;
            border-radius: 4px;
            padding: 2px 6px;
            font-family: monospace;
            font-size: 10px;
        }
    )");

    auto* lblSha256 = new QLabel("SHA256:", this);
    lblSha256->setStyleSheet("color: #22D3EE; font-weight: 600; font-family: monospace; font-size: 10px;");

    sha256Edit_ = new QLineEdit(this);
    sha256Edit_->setReadOnly(true);
    sha256Edit_->setStyleSheet(R"(
        QLineEdit {
            background-color: #0A1520;
            color: #94A3B8;
            border: 1px solid #1A2535;
            border-radius: 4px;
            padding: 2px 6px;
            font-family: monospace;
            font-size: 10px;
        }
    )");

    hashBar->addWidget(lblMd5);
    hashBar->addWidget(md5Edit_, 1);
    hashBar->addWidget(lblSha256);
    hashBar->addWidget(sha256Edit_, 2);

    layout->addLayout(hashBar);
}

QString HexView::formatHexDump(const QByteArray& data) {
    if (data.isEmpty()) return {};

    QString out;
    const int len = data.size();
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data.constData());

    for (int i = 0; i < len; i += 16) {
        // Offset
        out += QStringLiteral("%1  ").arg(i, 4, 16, QChar('0'));

        // Hex bytes
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                out += QStringLiteral("%1 ").arg(bytes[i + j], 2, 16, QChar('0'));
            } else {
                out += "   ";
            }
            if (j == 7) out += " ";
        }

        out += " |";

        // ASCII representation
        for (int j = 0; j < 16 && (i + j) < len; ++j) {
            char c = static_cast<char>(bytes[i + j]);
            out += (c >= 32 && c <= 126) ? c : '.';
        }

        out += "|\n";
    }

    return out;
}

void HexView::displayPacket(const PacketRecord& pkt) {
    if (pkt.no == 0) {
        clear();
        return;
    }

    QByteArray data = pkt.raw_bytes;
    if (data.isEmpty()) {
        // Generate simulated packet payload bytes matching the packet summary
        QString synthetic = QStringLiteral("[%1] %2 -> %3 (%4 bytes) Info: %5")
            .arg(pkt.protocolStr(), pkt.srcEndpoint(), pkt.dstEndpoint())
            .arg(pkt.length)
            .arg(pkt.infoStr());
        data = synthetic.toUtf8();
    }

    sizeLabel_->setText(QStringLiteral("%1 bytes").arg(data.size()));
    hexEdit_->setPlainText(formatHexDump(data));

    // Hashes
    QByteArray md5Hash = QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex();
    QByteArray sha256Hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();

    md5Edit_->setText(QString::fromLatin1(md5Hash));
    sha256Edit_->setText(QString::fromLatin1(sha256Hash));
}

void HexView::clear() {
    sizeLabel_->setText("");
    hexEdit_->clear();
    md5Edit_->clear();
    sha256Edit_->clear();
}

} // namespace SS
