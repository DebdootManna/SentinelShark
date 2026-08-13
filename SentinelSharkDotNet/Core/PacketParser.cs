using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public static class PacketParser
{
    public static PacketInfo ParseTSharkJsonPacket(JsonElement pktData, int number)
    {
        var packetInfo = new PacketInfo
        {
            No = number,
            Time = DateTime.Now.ToString("HH:mm:ss.ffffff")
        };

        if (pktData.TryGetProperty("_source", out JsonElement source) &&
            source.TryGetProperty("layers", out JsonElement layers))
        {
            // Frame info
            if (layers.TryGetProperty("frame", out JsonElement frame))
            {
                packetInfo.Time = SafeGetString(frame, "frame.time", packetInfo.Time);
                string lenStr = SafeGetString(frame, "frame.len", "0");
                if (int.TryParse(lenStr, out int length))
                {
                    packetInfo.Length = length;
                }
            }

            // IP Layer
            if (layers.TryGetProperty("ip", out JsonElement ip))
            {
                packetInfo.Source = SafeGetString(ip, "ip.src");
                packetInfo.Destination = SafeGetString(ip, "ip.dst");
                packetInfo.Protocol = "IPv4";
            }
            else if (layers.TryGetProperty("ipv6", out JsonElement ipv6))
            {
                packetInfo.Source = SafeGetString(ipv6, "ipv6.src");
                packetInfo.Destination = SafeGetString(ipv6, "ipv6.dst");
                packetInfo.Protocol = "IPv6";
            }

            // Transport Layer
            int srcPort = 0;
            int dstPort = 0;
            if (layers.TryGetProperty("tcp", out JsonElement tcp))
            {
                packetInfo.Protocol = "TCP";
                int.TryParse(SafeGetString(tcp, "tcp.srcport"), out srcPort);
                int.TryParse(SafeGetString(tcp, "tcp.dstport"), out dstPort);
                packetInfo.Info = $"TCP {srcPort} > {dstPort}";
            }
            else if (layers.TryGetProperty("udp", out JsonElement udp))
            {
                packetInfo.Protocol = "UDP";
                int.TryParse(SafeGetString(udp, "udp.srcport"), out srcPort);
                int.TryParse(SafeGetString(udp, "udp.dstport"), out dstPort);
                packetInfo.Info = $"UDP {srcPort} > {dstPort}";
            }

            // Application Layer
            if (layers.TryGetProperty("tls", out _))
            {
                packetInfo.Protocol = "TLS";
                packetInfo.Info = $"Application Data";
            }
            else if (layers.TryGetProperty("http", out JsonElement http))
            {
                packetInfo.Protocol = "HTTP";
                string method = SafeGetString(http, "http.request.method");
                string uri = SafeGetString(http, "http.request.uri");
                if (!string.IsNullOrEmpty(method))
                {
                    packetInfo.Info = $"HTTP {method} {uri}";
                }
            }
            else if (layers.TryGetProperty("dns", out JsonElement dns))
            {
                packetInfo.Protocol = "DNS";
                string qname = SafeGetString(dns, "dns.qry.name");
                packetInfo.Info = $"DNS Query {qname}";
            }
            else if (layers.TryGetProperty("icmp", out _))
            {
                packetInfo.Protocol = "ICMP";
                packetInfo.Info = "Echo (ping)";
            }
            else if (layers.TryGetProperty("arp", out _))
            {
                packetInfo.Protocol = "ARP";
                packetInfo.Info = "Who has?";
            }

            // Raw bytes
            if (layers.TryGetProperty("frame_raw", out JsonElement frameRaw))
            {
                string hexStr = frameRaw.GetString() ?? "";
                if (hexStr.Length % 2 != 0) hexStr = "0" + hexStr;
                byte[] raw = new byte[hexStr.Length / 2];
                for (int i = 0; i < raw.Length; i++)
                {
                    raw[i] = Convert.ToByte(hexStr.Substring(i * 2, 2), 16);
                }
                packetInfo.RawBytes = raw;

                var (hexDump, asciiDump) = FormatHexDump(raw);
                packetInfo.HexDump = hexDump;
                packetInfo.AsciiDump = asciiDump;

                var (md5, sha256) = CalculatePayloadHash(raw);
                packetInfo.PayloadHashMd5 = md5;
                packetInfo.PayloadHashSha256 = sha256;
            }
        }

        if (string.IsNullOrEmpty(packetInfo.Source)) packetInfo.Source = "Unknown";
        if (string.IsNullOrEmpty(packetInfo.Destination)) packetInfo.Destination = "Unknown";
        if (string.IsNullOrEmpty(packetInfo.Protocol)) packetInfo.Protocol = "ETH";
        if (string.IsNullOrEmpty(packetInfo.Info)) packetInfo.Info = "Unknown Payload";

        return packetInfo;
    }

    public static string SafeGetString(JsonElement element, string propertyName, string defaultValue = "")
    {
        if (element.TryGetProperty(propertyName, out JsonElement prop))
        {
            if (prop.ValueKind == JsonValueKind.Array && prop.GetArrayLength() > 0)
            {
                var first = prop[0];
                return first.ValueKind == JsonValueKind.String ? first.GetString() ?? defaultValue : first.GetRawText();
            }
            if (prop.ValueKind == JsonValueKind.String)
            {
                return prop.GetString() ?? defaultValue;
            }
            return prop.GetRawText();
        }
        return defaultValue;
    }

    public static (string hexDump, string asciiDump) FormatHexDump(byte[] data)
    {
        if (data == null || data.Length == 0) return ("", "");

        var hexBuilder = new StringBuilder();
        var asciiBuilder = new StringBuilder();

        for (int i = 0; i < data.Length; i += 16)
        {
            hexBuilder.Append($"{i:X4}  ");
            
            var asciiLine = new StringBuilder();
            
            for (int j = 0; j < 16; j++)
            {
                if (i + j < data.Length)
                {
                    byte b = data[i + j];
                    hexBuilder.Append($"{b:X2} ");
                    
                    if (b >= 0x20 && b <= 0x7E)
                    {
                        asciiLine.Append((char)b);
                    }
                    else
                    {
                        asciiLine.Append('.');
                    }
                }
                else
                {
                    hexBuilder.Append("   ");
                    asciiLine.Append(' ');
                }

                if (j == 7)
                {
                    hexBuilder.Append(" ");
                }
            }
            
            hexBuilder.Append($" |{asciiLine}|");
            hexBuilder.AppendLine();
            asciiBuilder.AppendLine(asciiLine.ToString().TrimEnd());
        }

        return (hexBuilder.ToString().TrimEnd(), asciiBuilder.ToString().TrimEnd());
    }

    public static (string md5, string sha256) CalculatePayloadHash(byte[] data)
    {
        if (data == null || data.Length == 0) return ("", "");

        using var md5Hasher = MD5.Create();
        using var sha256Hasher = SHA256.Create();

        byte[] md5Bytes = md5Hasher.ComputeHash(data);
        byte[] sha256Bytes = sha256Hasher.ComputeHash(data);

        return (Convert.ToHexString(md5Bytes).ToLower(), Convert.ToHexString(sha256Bytes).ToLower());
    }

    public static List<LayerNode> BuildLayersTree(JsonElement layers, string srcIp, string dstIp, int length, string time)
    {
        var rootLayers = new List<LayerNode>();

        if (layers.TryGetProperty("frame", out JsonElement frame))
        {
            rootLayers.Add(new LayerNode
            {
                Label = $"Frame: {length} bytes",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Arrival Time: {time}" },
                    new LayerNode { Label = $"Frame Length: {length} bytes" }
                }
            });
        }

        if (layers.TryGetProperty("eth", out JsonElement eth))
        {
            string srcMac = SafeGetString(eth, "eth.src");
            string dstMac = SafeGetString(eth, "eth.dst");
            rootLayers.Add(new LayerNode
            {
                Label = $"Ethernet II, Src: {srcMac}, Dst: {dstMac}",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Source: {srcMac}" },
                    new LayerNode { Label = $"Destination: {dstMac}" }
                }
            });
        }

        if (layers.TryGetProperty("ip", out JsonElement ip))
        {
            string src = SafeGetString(ip, "ip.src", srcIp);
            string dst = SafeGetString(ip, "ip.dst", dstIp);
            string ttl = SafeGetString(ip, "ip.ttl");
            string proto = SafeGetString(ip, "ip.proto");
            
            rootLayers.Add(new LayerNode
            {
                Label = $"Internet Protocol Version 4, Src: {src}, Dst: {dst}",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Source: {src}" },
                    new LayerNode { Label = $"Destination: {dst}" },
                    new LayerNode { Label = $"Time to live: {ttl}" },
                    new LayerNode { Label = $"Protocol: {proto}" }
                }
            });
        }
        else if (layers.TryGetProperty("ipv6", out JsonElement ipv6))
        {
            string src = SafeGetString(ipv6, "ipv6.src", srcIp);
            string dst = SafeGetString(ipv6, "ipv6.dst", dstIp);
            rootLayers.Add(new LayerNode
            {
                Label = $"Internet Protocol Version 6, Src: {src}, Dst: {dst}",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Source: {src}" },
                    new LayerNode { Label = $"Destination: {dst}" }
                }
            });
        }

        if (layers.TryGetProperty("tcp", out JsonElement tcp))
        {
            string srcPort = SafeGetString(tcp, "tcp.srcport");
            string dstPort = SafeGetString(tcp, "tcp.dstport");
            string seq = SafeGetString(tcp, "tcp.seq");
            string ack = SafeGetString(tcp, "tcp.ack");
            
            rootLayers.Add(new LayerNode
            {
                Label = $"Transmission Control Protocol, Src Port: {srcPort}, Dst Port: {dstPort}",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Source Port: {srcPort}" },
                    new LayerNode { Label = $"Destination Port: {dstPort}" },
                    new LayerNode { Label = $"Sequence Number: {seq}" },
                    new LayerNode { Label = $"Acknowledgment Number: {ack}" }
                }
            });
        }
        else if (layers.TryGetProperty("udp", out JsonElement udp))
        {
            string srcPort = SafeGetString(udp, "udp.srcport");
            string dstPort = SafeGetString(udp, "udp.dstport");
            
            rootLayers.Add(new LayerNode
            {
                Label = $"User Datagram Protocol, Src Port: {srcPort}, Dst Port: {dstPort}",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Source Port: {srcPort}" },
                    new LayerNode { Label = $"Destination Port: {dstPort}" }
                }
            });
        }
        
        if (layers.TryGetProperty("http", out JsonElement http))
        {
            string method = SafeGetString(http, "http.request.method");
            string uri = SafeGetString(http, "http.request.uri");
            string host = SafeGetString(http, "http.host");
            
            rootLayers.Add(new LayerNode
            {
                Label = $"Hypertext Transfer Protocol",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Method: {method}" },
                    new LayerNode { Label = $"URI: {uri}" },
                    new LayerNode { Label = $"Host: {host}" }
                }
            });
        }
        
        if (layers.TryGetProperty("dns", out JsonElement dns))
        {
            string qryName = SafeGetString(dns, "dns.qry.name");
            
            rootLayers.Add(new LayerNode
            {
                Label = $"Domain Name System",
                Children = new List<LayerNode>
                {
                    new LayerNode { Label = $"Query Name: {qryName}" }
                }
            });
        }

        return rootLayers;
    }
}
