using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public static class InterfaceMapper
{
    public static List<NetworkInterfaceInfo> GetNetworkInterfaces()
    {
        var result = new List<NetworkInterfaceInfo>();
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var ni in interfaces)
        {
            var props = ni.GetIPProperties();
            var ipv4 = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            
            result.Add(new NetworkInterfaceInfo
            {
                Id = ni.Id,
                Name = ni.Name,
                FriendlyName = ni.Description,
                IPv4Address = ipv4?.Address.ToString() ?? "",
                IsActive = ni.OperationalStatus == OperationalStatus.Up
            });
        }

        return result.OrderByDescending(i => i.IsActive).ThenBy(i => i.Name).ToList();
    }

    public static List<(string id, string description)> GetTSharkInterfaces()
    {
        var interfaces = new List<(string id, string description)>();
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "tshark.exe",
                Arguments = "-D",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd();
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    int dotIndex = line.IndexOf('.');
                    if (dotIndex >= 0)
                    {
                        string id = line.Substring(0, dotIndex).Trim();
                        string desc = line.Substring(dotIndex + 1).Trim();
                        interfaces.Add((id, desc));
                    }
                }
                process.WaitForExit();
            }
        }
        catch
        {
            // Ignore
        }
        return interfaces;
    }

    public static string MapToTSharkId(string friendlyName)
    {
        var tsharkInterfaces = GetTSharkInterfaces();
        foreach (var tsi in tsharkInterfaces)
        {
            if (tsi.description.Contains(friendlyName, StringComparison.OrdinalIgnoreCase) ||
                friendlyName.Contains(tsi.description, StringComparison.OrdinalIgnoreCase))
            {
                return tsi.id;
            }
        }
        return friendlyName; // Return original if not matched
    }

    public static (long bytesReceived, long bytesSent) GetTrafficDelta(string interfaceId)
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var ni = interfaces.FirstOrDefault(i => i.Id == interfaceId || i.Name == interfaceId || i.Description == interfaceId);
            
            if (ni != null)
            {
                var stats = ni.GetIPStatistics();
                return (stats.BytesReceived, stats.BytesSent);
            }
        }
        catch
        {
            // Ignored
        }
        return (0, 0);
    }
}
