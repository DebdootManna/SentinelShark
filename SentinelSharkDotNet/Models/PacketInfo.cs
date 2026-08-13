using System.Collections.Generic;

namespace SentinelSharkDotNet.Models;

public class PacketInfo
{
    public int No { get; set; }
    public string Time { get; set; } = "";
    public string Source { get; set; } = "";
    public string Destination { get; set; } = "";
    public string Protocol { get; set; } = "";
    public int Length { get; set; }
    public string Info { get; set; } = "";
    public int ThreatScore { get; set; }
    public string SourcePort { get; set; } = "";
    public string DestPort { get; set; } = "";
    public byte[]? RawBytes { get; set; }
    public string HexDump { get; set; } = "";
    public string AsciiDump { get; set; } = "";
    public string PayloadHashMd5 { get; set; } = "";
    public string PayloadHashSha256 { get; set; } = "";
    public List<LayerNode> LayersTree { get; set; } = new();
    public ThreatData? ThreatData { get; set; }
    public bool IsPublic { get; set; }
}
