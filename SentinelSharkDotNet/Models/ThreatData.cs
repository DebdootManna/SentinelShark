using System;
using System.Collections.Generic;

namespace SentinelSharkDotNet.Models;

public class ThreatData
{
    public int AbuseScore { get; set; }
    public int ReportsCount { get; set; }
    public int VtMalicious { get; set; }
    public int VtSuspicious { get; set; }
    public int VtHarmless { get; set; }
    public string Country { get; set; } = "";
    public string Domain { get; set; } = "";
    public string IpInfoOrg { get; set; } = "";
    public string IpInfoHostname { get; set; } = "";
    public string IpInfoCity { get; set; } = "";
    public string IpInfoRegion { get; set; } = "";
    public string IpInfoCountry { get; set; } = "";
    public string IpInfoLoc { get; set; } = "";
    public string IpInfoTimezone { get; set; } = "";
    public string IpInfoPostal { get; set; } = "";
    public string IpInfoAnycast { get; set; } = "";
    public List<int> ShodanPorts { get; set; } = new();
    public string ShodanOrg { get; set; } = "";
    public string ShodanOs { get; set; } = "";
    public List<string> ShodanHostnames { get; set; } = new();
    public List<string> ShodanTags { get; set; } = new();
    public List<string> ShodanVulns { get; set; } = new();
    public List<string> ShodanCpes { get; set; } = new();
    public string ShodanStatus { get; set; } = "";
    public string ShodanTier { get; set; } = "";
    public string ShodanCountry { get; set; } = "";
    public bool IsPublic { get; set; }
    public bool IsCached { get; set; }
    public string Ip { get; set; } = "";
    public bool Has429 { get; set; }
    public bool NoKeys { get; set; }
    public DateTime UpdatedAt { get; set; }
}
