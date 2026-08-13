using System;
using System.Collections.Generic;
using System.IO;

namespace SentinelSharkDotNet.Core;

public class AppConfig
{
    private static AppConfig? _instance;
    public static AppConfig Instance => _instance ??= new AppConfig();

    public string AbuseIpDbApiKey { get; set; } = "";
    public string VirusTotalApiKey { get; set; } = "";
    public string IpInfoApiKey { get; set; } = "";
    public string ShodanApiKey { get; set; } = "";
    public int CacheTtlHours { get; set; } = 24;
    public int MaxRequestsPerMinute { get; set; } = 30;
    public bool MockMode { get; set; } = false;
    public bool AutoScroll { get; set; } = true;
    public string TSharkPath { get; set; } = "";
    public string DefaultInterface { get; set; } = "auto";

    private readonly string _envFilePath;

    private AppConfig()
    {
        _envFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".env");
        Load();
    }

    public void Load()
    {
        var envVars = ParseEnvFile(_envFilePath);
        
        AbuseIpDbApiKey = GetValue(envVars, "ABUSEIPDB_API_KEY", Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY") ?? "");
        VirusTotalApiKey = GetValue(envVars, "VIRUSTOTAL_API_KEY", Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY") ?? "");
        IpInfoApiKey = GetValue(envVars, "IPINFO_API_KEY", Environment.GetEnvironmentVariable("IPINFO_API_KEY") ?? "");
        ShodanApiKey = GetValue(envVars, "SHODAN_API_KEY", Environment.GetEnvironmentVariable("SHODAN_API_KEY") ?? "");
        
        if (int.TryParse(GetValue(envVars, "CACHE_TTL_HOURS", Environment.GetEnvironmentVariable("CACHE_TTL_HOURS") ?? "24"), out int ttl))
            CacheTtlHours = ttl;
            
        if (int.TryParse(GetValue(envVars, "MAX_REQUESTS_PER_MINUTE", Environment.GetEnvironmentVariable("MAX_REQUESTS_PER_MINUTE") ?? "30"), out int maxReq))
            MaxRequestsPerMinute = maxReq;
            
        if (bool.TryParse(GetValue(envVars, "MOCK_MODE", Environment.GetEnvironmentVariable("MOCK_MODE") ?? "false"), out bool mockMode))
            MockMode = mockMode;
            
        if (bool.TryParse(GetValue(envVars, "AUTO_SCROLL", Environment.GetEnvironmentVariable("AUTO_SCROLL") ?? "true"), out bool autoScroll))
            AutoScroll = autoScroll;
            
        TSharkPath = GetValue(envVars, "TSHARK_PATH", Environment.GetEnvironmentVariable("TSHARK_PATH") ?? "");
        DefaultInterface = GetValue(envVars, "DEFAULT_INTERFACE", Environment.GetEnvironmentVariable("DEFAULT_INTERFACE") ?? "auto");
    }

    private string GetValue(Dictionary<string, string> envVars, string key, string defaultValue)
    {
        if (envVars.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        return defaultValue;
    }

    private Dictionary<string, string> ParseEnvFile(string path)
    {
        var result = new Dictionary<string, string>();
        if (!File.Exists(path)) return result;

        var lines = File.ReadAllLines(path);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#"))
                continue;

            var parts = trimmed.Split('=', 2);
            if (parts.Length == 2)
            {
                result[parts[0].Trim()] = parts[1].Trim();
            }
        }
        return result;
    }

    public void Save()
    {
        var updates = new Dictionary<string, string>
        {
            { "ABUSEIPDB_API_KEY", AbuseIpDbApiKey },
            { "VIRUSTOTAL_API_KEY", VirusTotalApiKey },
            { "IPINFO_API_KEY", IpInfoApiKey },
            { "SHODAN_API_KEY", ShodanApiKey },
            { "CACHE_TTL_HOURS", CacheTtlHours.ToString() },
            { "MAX_REQUESTS_PER_MINUTE", MaxRequestsPerMinute.ToString() },
            { "MOCK_MODE", MockMode.ToString().ToLower() },
            { "AUTO_SCROLL", AutoScroll.ToString().ToLower() },
            { "TSHARK_PATH", TSharkPath },
            { "DEFAULT_INTERFACE", DefaultInterface }
        };
        SaveEnvFile(_envFilePath, updates);
    }

    private void SaveEnvFile(string path, Dictionary<string, string> updates)
    {
        var existingLines = new List<string>();
        var updatedKeys = new HashSet<string>();

        if (File.Exists(path))
        {
            var lines = File.ReadAllLines(path);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#"))
                {
                    existingLines.Add(line);
                    continue;
                }

                var parts = trimmed.Split('=', 2);
                if (parts.Length == 2)
                {
                    var key = parts[0].Trim();
                    if (updates.TryGetValue(key, out var newValue))
                    {
                        existingLines.Add($"{key}={newValue}");
                        updatedKeys.Add(key);
                    }
                    else
                    {
                        existingLines.Add(line);
                    }
                }
                else
                {
                    existingLines.Add(line);
                }
            }
        }

        foreach (var kvp in updates)
        {
            if (!updatedKeys.Contains(kvp.Key))
            {
                existingLines.Add($"{kvp.Key}={kvp.Value}");
            }
        }

        File.WriteAllLines(path, existingLines);
    }

    public string FindTShark()
    {
        if (!string.IsNullOrWhiteSpace(TSharkPath) && File.Exists(TSharkPath))
            return TSharkPath;

        var defaultPath = @"C:\Program Files\Wireshark\tshark.exe";
        if (File.Exists(defaultPath))
            return defaultPath;

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var pathDir in pathEnv.Split(Path.PathSeparator))
        {
            var testPath = Path.Combine(pathDir, "tshark.exe");
            if (File.Exists(testPath))
                return testPath;
        }

        return "";
    }

    public bool IsTSharkAvailable => !string.IsNullOrEmpty(FindTShark());
}
