using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SentinelSharkDotNet.Models;

public class PacketInfo : INotifyPropertyChanged
{
    private int _no;
    private string _time = "";
    private string _source = "";
    private string _destination = "";
    private string _protocol = "";
    private int _length;
    private string _info = "";
    private int _threatScore;
    private ThreatData? _threatData;

    public int No { get => _no; set { _no = value; OnPropertyChanged(); } }
    public string Time { get => _time; set { _time = value; OnPropertyChanged(); } }
    public string Source { get => _source; set { _source = value; OnPropertyChanged(); } }
    public string Destination { get => _destination; set { _destination = value; OnPropertyChanged(); } }
    public string Protocol { get => _protocol; set { _protocol = value; OnPropertyChanged(); } }
    public int Length { get => _length; set { _length = value; OnPropertyChanged(); } }
    public string Info { get => _info; set { _info = value; OnPropertyChanged(); } }
    
    public int ThreatScore
    {
        get => _threatScore;
        set
        {
            if (_threatScore != value)
            {
                _threatScore = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ThreatScoreDisplay));
                OnPropertyChanged(nameof(IsCriticalThreat));
                OnPropertyChanged(nameof(IsHighRiskThreat));
                OnPropertyChanged(nameof(IsLowRiskThreat));
                OnPropertyChanged(nameof(IsSafePublicIp));
            }
        }
    }

    public ThreatData? ThreatData
    {
        get => _threatData;
        set
        {
            _threatData = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ThreatScoreDisplay));
            OnPropertyChanged(nameof(IsCriticalThreat));
            OnPropertyChanged(nameof(IsHighRiskThreat));
            OnPropertyChanged(nameof(IsLowRiskThreat));
            OnPropertyChanged(nameof(IsSafePublicIp));
        }
    }

    public string ThreatScoreDisplay
    {
        get
        {
            if (_threatScore == 0) return "0% Safe";
            return $"{_threatScore}% Risk";
        }
    }

    public bool IsCriticalThreat => _threatScore >= 90;
    public bool IsHighRiskThreat => _threatScore >= 50 && _threatScore < 90;
    public bool IsLowRiskThreat => _threatScore > 0 && _threatScore < 50;
    public bool IsSafePublicIp => _threatData != null && _threatData.IsPublic && _threatScore == 0;

    public string SourcePort { get; set; } = "";
    public string DestPort { get; set; } = "";
    public byte[]? RawBytes { get; set; }
    public string HexDump { get; set; } = "";
    public string AsciiDump { get; set; } = "";
    public string PayloadHashMd5 { get; set; } = "";
    public string PayloadHashSha256 { get; set; } = "";
    public List<LayerNode> LayersTree { get; set; } = new();
    public bool IsPublic { get; set; }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
