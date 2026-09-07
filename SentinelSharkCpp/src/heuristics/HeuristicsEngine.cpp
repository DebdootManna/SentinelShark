#include "HeuristicsEngine.h"
#include <unordered_set>
#include <unordered_map>
#include <string>

namespace SS {

// ── Static data (initialized once, zero-overhead thereafter) ─────────────────

static const std::unordered_set<std::string> kLolbins = {
    "bash", "sh", "zsh",
    "python", "python3",
    "python3.10", "python3.11", "python3.12", "python3.13", "python3.14",
    "curl", "wget",
    "powershell.exe", "powershell",
    "cmd.exe", "cmd",
    "nc", "ncat", "socat",
    "ruby", "perl", "node",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe",
};

/// Maps process base name -> primary MITRE technique ID
static const std::unordered_map<std::string, std::string> kPrimaryTechnique = {
    {"bash",         "T1059"}, {"sh",      "T1059"}, {"zsh",     "T1059"},
    {"python",       "T1059"}, {"python3", "T1059"},
    {"python3.10",   "T1059"}, {"python3.11","T1059"}, {"python3.12","T1059"},
    {"python3.13",   "T1059"}, {"python3.14","T1059"},
    {"powershell.exe","T1059"}, {"powershell","T1059"},
    {"cmd.exe",      "T1059"}, {"cmd",     "T1059"},
    {"wscript.exe",  "T1059"}, {"cscript.exe","T1059"},
    {"mshta.exe",    "T1059"},
    {"curl",         "T1105"}, {"wget",        "T1105"},
    {"certutil.exe", "T1105"}, {"bitsadmin.exe","T1105"},
    {"nc",           "T1095"}, {"ncat",    "T1095"}, {"socat",   "T1095"},
    {"regsvr32.exe", "T1218"}, {"rundll32.exe","T1218"},
};

static const std::unordered_map<std::string, std::string> kTechniqueNames = {
    {"T1071",     "App Layer Protocol"},
    {"T1071.001", "Web Protocols"},
    {"T1071.004", "DNS Protocol"},
    {"T1059",     "Command & Scripting"},
    {"T1059.001", "PowerShell"},
    {"T1105",     "Ingress Tool Transfer"},
    {"T1095",     "Non-App Layer Protocol"},
    {"T1571",     "Non-Standard Port"},
    {"T1021.004", "SSH Remote Services"},
    {"T1021.001", "RDP"},
    {"T1021.002", "SMB/Windows Admin Shares"},
    {"T1218",     "System Binary Proxy Exec"},
    {"T1567",     "Exfiltration Over Web Service"},
    {"T1090.003", "Multi-hop Proxy"},
    {"T1537",     "Transfer Data to Cloud Account"},
};

static const std::unordered_set<std::string> kHighRiskTags = {
    "T1059", "T1105", "T1095", "T1218"
};

// ── HeuristicsEngine implementation ──────────────────────────────────────────

bool HeuristicsEngine::isLolbin(const QString& processName) {
    return kLolbins.count(processName.toLower().toStdString()) > 0;
}

QStringList HeuristicsEngine::evaluate(const QString& processName,
                                        const QString& proto,
                                        uint16_t       dstPort)
{
    QStringList tags;
    const std::string proc = processName.toLower().toStdString();
    const bool lolbin      = kLolbins.count(proc) > 0;
    const QString protUp   = proto.toUpper();

    // ── LOLBin primary technique ────────────────────────────────────────────
    if (lolbin) {
        auto it = kPrimaryTechnique.find(proc);
        if (it != kPrimaryTechnique.end())
            tags << QString::fromStdString(it->second);
    }

    // ── Protocol / port rules ───────────────────────────────────────────────
    if (protUp == "DNS" || dstPort == 53) {
        tags << "T1071.004";
    } else if (protUp == "HTTP" || dstPort == 80) {
        tags << "T1071.001";
        if (dstPort != 80 && dstPort != 0)
            tags << "T1571"; // non-standard port for HTTP-like traffic
    } else if (protUp == "HTTPS" || dstPort == 443) {
        tags << "T1071";
    } else if (protUp == "SSH" || dstPort == 22) {
        tags << "T1021.004";
    } else if (protUp == "RDP" || dstPort == 3389) {
        tags << "T1021.001";
    } else if (protUp == "SMB" || dstPort == 445) {
        tags << "T1021.002";
    } else if (dstPort != 0 && dstPort != 80 && dstPort != 443 && lolbin) {
        // LOLBin making connection on non-standard port
        tags << "T1571";
    }

    // Deduplicate while preserving order
    QStringList unique;
    for (const auto& t : std::as_const(tags))
        if (!unique.contains(t))
            unique << t;

    return unique;
}

Severity HeuristicsEngine::computeSeverity(int                abuseScore,
                                            int                vtMalicious,
                                            const QStringList& mitreTags,
                                            bool               isLolbinProcess)
{
    const bool hasHighRisk = std::any_of(mitreTags.begin(), mitreTags.end(),
        [](const QString& t) { return kHighRiskTags.count(t.toStdString()) > 0; });

    // Critical thresholds
    if (abuseScore >= 80)                                    return Severity::Critical;
    if (vtMalicious >= 5)                                    return Severity::Critical;
    if (isLolbinProcess && mitreTags.size() > 1)             return Severity::Critical;

    // High thresholds
    if (abuseScore >= 40)                                    return Severity::High;
    if (vtMalicious >= 2)                                    return Severity::High;
    if (isLolbinProcess && hasHighRisk)                      return Severity::High;

    // Medium thresholds
    if (abuseScore > 0)                                      return Severity::Medium;
    if (mitreTags.contains("T1571"))                         return Severity::Medium;
    if (mitreTags.contains("T1071.001"))                     return Severity::Medium;
    if (isLolbinProcess)                                     return Severity::Medium;

    return Severity::Safe;
}

QString HeuristicsEngine::techniqueDescription(const QString& techniqueId) {
    auto it = kTechniqueNames.find(techniqueId.toStdString());
    if (it != kTechniqueNames.end())
        return QString::fromStdString(it->second);
    return techniqueId; // fallback: return the ID itself
}

} // namespace SS
