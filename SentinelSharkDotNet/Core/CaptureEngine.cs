using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public class CaptureEngine
{
    private Process? _tsharkProcess;
    private CancellationTokenSource? _cts;
    private bool _isCapturing;
    private string _currentInterface = string.Empty;
    private string _bpfFilter = string.Empty;

    public event Action<PacketInfo>? PacketReceived;
    public event Action<List<PacketInfo>>? PacketBatchReceived;
    public event Action<string>? StatusChanged;
    public event Action<string>? ErrorOccurred;
    public event Action<string>? PermissionError;

    public void StartCapture(string interfaceName, string bpfFilter = "")
    {
        if (AppConfig.Instance.MockMode)
        {
            StartMockCapture();
            return;
        }

        string? tsharkPath = AppConfig.Instance.FindTShark();
        if (tsharkPath == null)
        {
            StatusChanged?.Invoke("TShark not found. Switching to Mock Capture mode.");
            StartMockCapture();
            return;
        }
        _currentInterface = interfaceName;
        _bpfFilter = SanitizeBpfFilter(bpfFilter);

        try
        {
            _cts = new CancellationTokenSource();
            _isCapturing = true;

            string tsharkIface = InterfaceMapper.MapToTSharkId(interfaceName);
            string args = $"-i \"{tsharkIface}\" -l -T json -x";
            if (!string.IsNullOrEmpty(_bpfFilter))
            {
                args += $" -f \"{_bpfFilter}\"";
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = tsharkPath,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            _tsharkProcess = Process.Start(startInfo);
            if (_tsharkProcess == null)
            {
                StatusChanged?.Invoke("Failed to start tshark process. Switching to Mock Capture mode.");
                StartMockCapture();
                return;
            }

            StatusChanged?.Invoke($"Started capture on {interfaceName}");

            Task.Run(() => ReadTsharkOutput(_tsharkProcess.StandardOutput, _cts.Token), _cts.Token);
            Task.Run(() => ReadTsharkError(_tsharkProcess.StandardError, _cts.Token), _cts.Token);

            Task.Run(async () =>
            {
                await Task.Delay(500);
                if (_tsharkProcess != null && _tsharkProcess.HasExited)
                {
                    StatusChanged?.Invoke($"TShark process exited. Switching to Mock Capture mode.");
                    StartMockCapture();
                }
            }, _cts.Token);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Error starting capture: {ex.Message}. Switching to Mock Capture mode.");
            StartMockCapture();
        }
    }

    public void StartPcapCapture(string filePath)
    {
        string? tsharkPath = AppConfig.Instance.FindTShark();
        if (tsharkPath == null)
        {
            ErrorOccurred?.Invoke("TShark not found! Please install Wireshark with Npcap from https://www.wireshark.org/download.html");
            return;
        }
        try
        {
            _cts = new CancellationTokenSource();
            _isCapturing = true;

            string args = $"-r \"{filePath}\" -T json -x";

            var startInfo = new ProcessStartInfo
            {
                FileName = tsharkPath,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            _tsharkProcess = Process.Start(startInfo);
            if (_tsharkProcess == null)
            {
                ErrorOccurred?.Invoke("Failed to start tshark process for PCAP.");
                return;
            }

            StatusChanged?.Invoke($"Started reading PCAP file {Path.GetFileName(filePath)}");

            Task.Run(() => ReadTsharkOutput(_tsharkProcess.StandardOutput, _cts.Token), _cts.Token);
            Task.Run(() => ReadTsharkError(_tsharkProcess.StandardError, _cts.Token), _cts.Token);
        }
        catch (Exception ex)
        {
            ErrorOccurred?.Invoke($"Error reading PCAP: {ex.Message}");
            _isCapturing = false;
        }
    }

    public void StartMockCapture()
    {
        _cts = new CancellationTokenSource();
        _isCapturing = true;
        StatusChanged?.Invoke("Started mock capture");

        Task.Run(async () =>
        {
            var random = new Random();
            int packetNumber = 1;
            var batch = new List<PacketInfo>();
            var lastFlush = DateTime.UtcNow;

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(random.Next(20, 40), _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                byte[] raw = new byte[random.Next(64, 1500)];
                random.NextBytes(raw);
                var (hex, ascii) = PacketParser.FormatHexDump(raw);
                var (md5, sha256) = PacketParser.CalculatePayloadHash(raw);

                string[] mockProtos = new[] { "TCP", "UDP", "DNS", "TLS", "HTTP", "HTTPS", "SSH", "ICMP", "ARP", "QUIC" };
                string proto = mockProtos[random.Next(mockProtos.Length)];
                int threat = random.NextDouble() < 0.08 ? random.Next(45, 99) : 0;

                var pkt = new PacketInfo
                {
                    No = packetNumber++,
                    Time = DateTime.Now.ToString("HH:mm:ss.ffffff"),
                    Source = $"192.168.1.{random.Next(1, 255)}",
                    Destination = threat > 0 ? $"{random.Next(1, 220)}.{random.Next(1, 255)}.{random.Next(1, 255)}.{random.Next(1, 255)}" : $"10.0.0.{random.Next(1, 255)}",
                    Protocol = proto,
                    Length = raw.Length,
                    Info = threat > 0 ? $"Port scan / SYN flood candidate [Threat Score: {threat}%]" : $"{proto} data packet #{packetNumber}",
                    ThreatScore = threat,
                    RawBytes = raw,
                    HexDump = hex,
                    AsciiDump = ascii,
                    PayloadHashMd5 = md5,
                    PayloadHashSha256 = sha256,
                    IsPublic = threat > 0
                };

                PacketReceived?.Invoke(pkt);
                batch.Add(pkt);

                if (batch.Count >= 20 || (DateTime.UtcNow - lastFlush).TotalMilliseconds > 40)
                {
                    var batchCopy = new List<PacketInfo>(batch);
                    Application.Current?.Dispatcher.InvokeAsync(() => PacketBatchReceived?.Invoke(batchCopy));
                    batch.Clear();
                    lastFlush = DateTime.UtcNow;
                }
            }
        }, _cts.Token);
    }

    public void StopCapture()
    {
        _isCapturing = false;
        _cts?.Cancel();
        
        try
        {
            if (_tsharkProcess != null && !_tsharkProcess.HasExited)
            {
                _tsharkProcess.Kill();
            }
        }
        catch { /* Ignore kill errors */ }

        StatusChanged?.Invoke("Capture stopped.");
    }

    private async Task ReadTsharkOutput(StreamReader reader, CancellationToken token)
    {
        var buffer = new char[4096];
        var jsonBuilder = new System.Text.StringBuilder();
        int braceCount = 0;
        bool inQuotes = false;
        bool isEscaped = false;
        int packetNumber = 1;
        var batch = new List<PacketInfo>();
        var lastFlush = DateTime.UtcNow;

        try
        {
            while (!token.IsCancellationRequested)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    // Flush remaining batch
                    if (batch.Count > 0)
                    {
                        var batchCopy = new List<PacketInfo>(batch);
                        Application.Current?.Dispatcher.InvokeAsync(() => PacketBatchReceived?.Invoke(batchCopy));
                    }
                    break;
                }

                for (int i = 0; i < read; i++)
                {
                    char c = buffer[i];
                    jsonBuilder.Append(c);

                    if (!isEscaped && c == '"')
                    {
                        inQuotes = !inQuotes;
                    }

                    if (!inQuotes)
                    {
                        if (c == '{') braceCount++;
                        else if (c == '}') braceCount--;
                    }

                    isEscaped = (c == '\\' && !isEscaped);

                    if (braceCount == 0 && jsonBuilder.Length > 0 && c == '}')
                    {
                        string jsonString = jsonBuilder.ToString();
                        jsonBuilder.Clear();

                        int firstBrace = jsonString.IndexOf('{');
                        int lastBrace = jsonString.LastIndexOf('}');

                        if (firstBrace >= 0 && lastBrace > firstBrace)
                        {
                            string objectJson = jsonString.Substring(firstBrace, lastBrace - firstBrace + 1);
                            try
                            {
                                using var doc = JsonDocument.Parse(objectJson);
                                var pkt = PacketParser.ParseTSharkJsonPacket(doc.RootElement, packetNumber++);
                                if (pkt != null)
                                {
                                    PacketReceived?.Invoke(pkt);
                                    batch.Add(pkt);

                                    if (batch.Count >= 20 || (DateTime.UtcNow - lastFlush).TotalMilliseconds > 40)
                                    {
                                        var batchCopy = new List<PacketInfo>(batch);
                                        Application.Current?.Dispatcher.InvokeAsync(() => PacketBatchReceived?.Invoke(batchCopy));
                                        batch.Clear();
                                        lastFlush = DateTime.UtcNow;
                                    }
                                }
                            }
                            catch (Exception)
                            {
                                // Ignore json parse errors for fragments
                            }
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            ErrorOccurred?.Invoke($"Error reading output: {ex.Message}");
        }
    }

    private async Task ReadTsharkError(StreamReader reader, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                string? line = await reader.ReadLineAsync();
                if (line == null) break;
                
                if (line.Contains("permission denied", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("not permitted", StringComparison.OrdinalIgnoreCase))
                {
                    PermissionError?.Invoke(line);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    public string SanitizeBpfFilter(string rawFilter)
    {
        if (string.IsNullOrWhiteSpace(rawFilter)) return string.Empty;

        string lower = rawFilter.Trim().ToLowerInvariant();
        
        switch (lower)
        {
            case "http": return "tcp port 80 or tcp port 8080";
            case "https":
            case "ssl":
            case "tls": return "tcp port 443";
            case "dns": return "udp port 53 or tcp port 53";
            case "ssh": return "tcp port 22";
            case "icmp": return "icmp";
        }

        if (System.Net.IPAddress.TryParse(lower, out _))
        {
            return $"host {lower}";
        }

        return rawFilter;
    }

    public List<string> GetAvailableInterfaces()
    {
        var interfaces = new List<string>();
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
                    interfaces.Add(line);
                }
                process.WaitForExit();
            }
        }
        catch
        {
            // fallback
        }
        return interfaces;
    }
}
