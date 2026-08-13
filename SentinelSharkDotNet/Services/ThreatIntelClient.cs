using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using SentinelSharkDotNet.Models;
using SentinelSharkDotNet.Core;

namespace SentinelSharkDotNet.Services;

public class ThreatIntelClient
{
    private static readonly HttpClient _httpClient = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    public bool IsPublicIp(string ipStr)
    {
        if (string.IsNullOrWhiteSpace(ipStr) || !IPAddress.TryParse(ipStr, out var ip))
            return false;

        byte[] bytes = ip.GetAddressBytes();

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (bytes[0] == 0) return false;
            if (bytes[0] == 10) return false;
            if (bytes[0] == 127) return false;
            if (bytes[0] == 169 && bytes[1] == 254) return false;
            if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31)) return false;
            if (bytes[0] == 192 && bytes[1] == 168) return false;
            if (bytes[0] >= 224) return false;
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return false;
        }
        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
            if (bytes.All(b => b == 0)) return false;
            if (bytes.Take(15).All(b => b == 0) && bytes[15] == 1) return false;
        }
        else
        {
            return false;
        }

        return true;
    }

    public async Task<ThreatData> FetchAbuseIpDb(string ip)
    {
        var result = new ThreatData();
        var key = AppConfig.Instance.AbuseIpDbApiKey;
        if (string.IsNullOrWhiteSpace(key)) return result;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
            request.Headers.Add("Key", key);
            request.Headers.Add("Accept", "application/json");

            using var response = await _httpClient.SendAsync(request);
            if ((int)response.StatusCode == 429)
            {
                result.Has429 = true;
                return result;
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonNode.Parse(content);
                var data = json?["data"];
                if (data != null)
                {
                    result.AbuseScore = data["abuseConfidenceScore"]?.GetValue<int>() ?? 0;
                    result.ReportsCount = data["totalReports"]?.GetValue<int>() ?? 0;
                    result.Country = data["countryCode"]?.GetValue<string>();
                    result.Domain = data["domain"]?.GetValue<string>();
                }
            }
        }
        catch { }
        return result;
    }

    public async Task<ThreatData> FetchVirusTotal(string ip)
    {
        var result = new ThreatData();
        var key = AppConfig.Instance.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(key)) return result;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/ipaddresses/{ip}");
            request.Headers.Add("x-apikey", key);
            request.Headers.Add("Accept", "application/json");

            using var response = await _httpClient.SendAsync(request);
            if ((int)response.StatusCode == 429)
            {
                result.Has429 = true;
                return result;
            }
            if ((int)response.StatusCode == 404)
            {
                result.VtMalicious = 0;
                result.VtSuspicious = 0;
                result.VtHarmless = 0;
                return result;
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonNode.Parse(content);
                var stats = json?["data"]?["attributes"]?["last_analysis_stats"];
                if (stats != null)
                {
                    result.VtMalicious = stats["malicious"]?.GetValue<int>() ?? 0;
                    result.VtSuspicious = stats["suspicious"]?.GetValue<int>() ?? 0;
                    result.VtHarmless = stats["harmless"]?.GetValue<int>() ?? 0;
                }
            }
        }
        catch { }
        return result;
    }

    public async Task<ThreatData> FetchIpInfo(string ip)
    {
        var result = new ThreatData();
        var key = AppConfig.Instance.IpInfoApiKey;
        
        try
        {
            var url = $"https://ipinfo.io/{ip}/json";
            if (!string.IsNullOrWhiteSpace(key))
            {
                url += $"?token={key}";
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            if (!string.IsNullOrWhiteSpace(key))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", key);
            }

            using var response = await _httpClient.SendAsync(request);
            if ((int)response.StatusCode == 429)
            {
                result.Has429 = true;
                return result;
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonNode.Parse(content);
                if (json != null)
                {
                    result.IpInfoOrg = json["org"]?.GetValue<string>();
                    result.IpInfoHostname = json["hostname"]?.GetValue<string>();
                    result.IpInfoCity = json["city"]?.GetValue<string>();
                    result.IpInfoRegion = json["region"]?.GetValue<string>();
                    result.IpInfoCountry = json["country"]?.GetValue<string>();
                    result.IpInfoLoc = json["loc"]?.GetValue<string>();
                    result.IpInfoTimezone = json["timezone"]?.GetValue<string>();
                    result.IpInfoPostal = json["postal"]?.GetValue<string>();
                    result.IpInfoAnycast = (json["anycast"]?.GetValue<bool>() ?? false).ToString();
                }
            }
        }
        catch { }
        return result;
    }

    public async Task<ThreatData> FetchShodan(string ip)
    {
        var key = AppConfig.Instance.ShodanApiKey;
        if (string.IsNullOrWhiteSpace(key) || ip.Contains(':'))
        {
            return await FetchShodanInternetDb(ip);
        }

        var result = new ThreatData();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.shodan.io/shodan/host/{ip}?key={key}");
            using var response = await _httpClient.SendAsync(request);

            if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
            {
                var fallback = await FetchShodanInternetDb(ip);
                if ((int)response.StatusCode == 401) fallback.ShodanStatus = "Invalid Key (InternetDB Fallback)";
                return fallback;
            }
            if ((int)response.StatusCode == 429)
            {
                var fallback = await FetchShodanInternetDb(ip);
                fallback.Has429 = true;
                return fallback;
            }
            if ((int)response.StatusCode == 404)
            {
                return await FetchShodanInternetDb(ip);
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonNode.Parse(content);
                if (json != null)
                {
                    var portsNode = json["ports"] as JsonArray;
                    if (portsNode != null)
                        result.ShodanPorts = portsNode.Select(p => p.GetValue<int>()).ToList();
                    
                    result.ShodanOrg = json["org"]?.GetValue<string>();
                    result.ShodanOs = json["os"]?.GetValue<string>();
                    
                    var hostnamesNode = json["hostnames"] as JsonArray;
                    if (hostnamesNode != null)
                        result.ShodanHostnames = hostnamesNode.Select(h => h.GetValue<string>()).ToList();
                        
                    var tagsNode = json["tags"] as JsonArray;
                    if (tagsNode != null)
                        result.ShodanTags = tagsNode.Select(t => t.GetValue<string>()).ToList();

                    var vulnsNode = json["vulns"] as JsonArray;
                    if (vulnsNode != null)
                        result.ShodanVulns = vulnsNode.Select(v => v.GetValue<string>()).ToList();

                    result.ShodanCountry = json["country_code"]?.GetValue<string>();
                    result.ShodanStatus = "Standard Host API (Paid Tier)";
                    result.ShodanTier = "Premium (Standard Host API)";
                }
            }
        }
        catch 
        {
            return await FetchShodanInternetDb(ip);
        }
        return result;
    }

    public async Task<ThreatData> FetchShodanInternetDb(string ip)
    {
        var result = new ThreatData();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://internetdb.shodan.io/{ip}");
            using var response = await _httpClient.SendAsync(request);

            if ((int)response.StatusCode == 404)
            {
                result.ShodanStatus = "No Public Ports / Unindexed Host";
                result.ShodanPorts = new List<int>();
                result.ShodanVulns = new List<string>();
                return result;
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var json = JsonNode.Parse(content);
                if (json != null)
                {
                    var portsNode = json["ports"] as JsonArray;
                    if (portsNode != null)
                        result.ShodanPorts = portsNode.Select(p => p.GetValue<int>()).ToList();
                    
                    var cpesNode = json["cpes"] as JsonArray;
                    if (cpesNode != null)
                        result.ShodanCpes = cpesNode.Select(c => c.GetValue<string>()).ToList();

                    var hostnamesNode = json["hostnames"] as JsonArray;
                    if (hostnamesNode != null)
                        result.ShodanHostnames = hostnamesNode.Select(h => h.GetValue<string>()).ToList();

                    var tagsNode = json["tags"] as JsonArray;
                    if (tagsNode != null)
                        result.ShodanTags = tagsNode.Select(t => t.GetValue<string>()).ToList();

                    var vulnsNode = json["vulns"] as JsonArray;
                    if (vulnsNode != null)
                        result.ShodanVulns = vulnsNode.Select(v => v.GetValue<string>()).ToList();

                    result.ShodanStatus = "InternetDB Mode (Free Tier)";
                    result.ShodanTier = "Free (InternetDB Fallback)";
                }
            }
        }
        catch { }
        return result;
    }

    public async Task<ThreatData> LookupIp(string ip)
    {
        if (!IsPublicIp(ip))
        {
            return new ThreatData 
            {
                AbuseScore = 0,
                Country = "LOCAL",
                Domain = "Internal/Non-routable",
                IsPublic = false
            };
        }

        var result = new ThreatData { IsPublic = true };

        var abuse = await FetchAbuseIpDb(ip);
        var vt = await FetchVirusTotal(ip);
        var ipinfo = await FetchIpInfo(ip);
        var shodan = await FetchShodan(ip);

        result.AbuseScore = abuse.AbuseScore;
        result.ReportsCount = abuse.ReportsCount;
        
        result.VtMalicious = vt.VtMalicious;
        result.VtSuspicious = vt.VtSuspicious;
        result.VtHarmless = vt.VtHarmless;

        result.IpInfoOrg = ipinfo.IpInfoOrg;
        result.IpInfoHostname = ipinfo.IpInfoHostname;
        result.IpInfoCity = ipinfo.IpInfoCity;
        result.IpInfoRegion = ipinfo.IpInfoRegion;
        result.IpInfoCountry = ipinfo.IpInfoCountry;
        result.IpInfoLoc = ipinfo.IpInfoLoc;
        result.IpInfoTimezone = ipinfo.IpInfoTimezone;
        result.IpInfoPostal = ipinfo.IpInfoPostal;
        result.IpInfoAnycast = ipinfo.IpInfoAnycast;

        result.ShodanPorts = shodan.ShodanPorts ?? new List<int>();
        result.ShodanOrg = shodan.ShodanOrg;
        result.ShodanOs = shodan.ShodanOs;
        result.ShodanHostnames = shodan.ShodanHostnames ?? new List<string>();
        result.ShodanTags = shodan.ShodanTags ?? new List<string>();
        result.ShodanVulns = shodan.ShodanVulns ?? new List<string>();
        result.ShodanCountry = shodan.ShodanCountry;
        result.ShodanStatus = shodan.ShodanStatus;
        result.ShodanTier = shodan.ShodanTier;
        result.ShodanCpes = shodan.ShodanCpes ?? new List<string>();

        result.Country = !string.IsNullOrWhiteSpace(abuse.Country) ? abuse.Country :
                         !string.IsNullOrWhiteSpace(shodan.ShodanCountry) ? shodan.ShodanCountry :
                         ipinfo.IpInfoCountry;

        result.Domain = !string.IsNullOrWhiteSpace(abuse.Domain) ? abuse.Domain :
                        (shodan.ShodanHostnames?.FirstOrDefault()) ??
                        (!string.IsNullOrWhiteSpace(shodan.ShodanOrg) ? shodan.ShodanOrg :
                        (!string.IsNullOrWhiteSpace(ipinfo.IpInfoHostname) ? ipinfo.IpInfoHostname :
                        ipinfo.IpInfoOrg));

        int vtScore = result.VtMalicious > 0 ? Math.Min(result.VtMalicious * 20, 100) : 0;
        // CompositeScore removed as per instructions

        result.Has429 = abuse.Has429 || vt.Has429 || ipinfo.Has429 || shodan.Has429;

        return result;
    }
}
