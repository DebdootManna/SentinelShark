using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using System.Text;
using SentinelSharkDotNet.Models;
using SentinelSharkDotNet.Core;
using SentinelSharkDotNet.Services;

namespace SentinelSharkDotNet.UI;

public partial class MainWindow : Window
{
    private CaptureEngine _captureEngine;
    private ThreatQueueManager _queueManager;
    private ObservableCollection<PacketInfo> _packets;
    private int _packetCounter;
    private long _totalBytes;
    private int _safePackets;
    private int _threatsDetected;
    private Dictionary<string, int> _protocolCounts;
    private Dictionary<string, List<int>> _ipRowMap;
    private PacketInfo? _selectedPacket;
    private DispatcherTimer _startupTimer;

    public MainWindow()
    {
        InitializeComponent();

        _packets = new ObservableCollection<PacketInfo>();
        _protocolCounts = new Dictionary<string, int>();
        _ipRowMap = new Dictionary<string, List<int>>();
        
        PacketGrid.ItemsSource = _packets;

        _captureEngine = new CaptureEngine();
        _captureEngine.PacketReceived += CaptureEngine_OnPacketReceived;
        _captureEngine.PacketBatchReceived += CaptureEngine_OnPacketBatchReceived;
        _captureEngine.StatusChanged += CaptureEngine_OnStatusChanged;
        _captureEngine.ErrorOccurred += CaptureEngine_OnErrorOccurred;
        _captureEngine.PermissionError += CaptureEngine_OnPermissionError;

        _queueManager = new ThreatQueueManager();
        _queueManager.ThreatResolved += QueueManager_OnThreatResolved;
        _queueManager.QueueStatusChanged += QueueManager_OnQueueStatusChanged;

        LoadInterfaces();
        CheckTSharkStatus();

        this.ContentRendered += MainWindow_ContentRendered;
    }

    private void LoadInterfaces()
    {
        var interfaces = InterfaceMapper.GetNetworkInterfaces().Select(i => i.Name).ToList();
        InterfaceCombo.ItemsSource = interfaces;
        if (interfaces.Count > 0)
        {
            InterfaceCombo.SelectedIndex = 0;
        }
    }

    private void CheckTSharkStatus()
    {
        bool isAvailable = AppConfig.Instance.IsTSharkAvailable;
        if (isAvailable)
        {
            TSharkStatusDot.Fill = (Brush)FindResource("SafeGreenBrush");
            TSharkStatusText.Text = "TShark available";
        }
        else
        {
            TSharkStatusDot.Fill = (Brush)FindResource("CriticalRedBrush");
            TSharkStatusText.Text = "TShark not found";
        }
    }

    private void MainWindow_ContentRendered(object? sender, EventArgs e)
    {
        _startupTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(200)
        };
        _startupTimer.Tick += StartupTimer_Tick;
        _startupTimer.Start();
    }

    private void StartupTimer_Tick(object? sender, EventArgs e)
    {
        _startupTimer.Stop();
        
        var dialog = new InterfaceSelectionDialog();
        dialog.Owner = this;
        if (dialog.ShowDialog() == true)
        {
            if (!string.IsNullOrEmpty(dialog.SelectedInterface))
            {
                foreach (var item in InterfaceCombo.Items)
                {
                    if (item != null && (item.ToString() == dialog.SelectedInterface || item.ToString()!.Contains(dialog.SelectedInterface)))
                    {
                        InterfaceCombo.SelectedItem = item;
                        break;
                    }
                }
            }
            StartBtn_Click(this, new RoutedEventArgs());
        }
    }

    private void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (InterfaceCombo.SelectedItem is string selectedInterface)
        {
            string filter = BpfFilterBox.Text;
            _captureEngine.StartCapture(selectedInterface, filter);
            _queueManager.Start();
        }
        else
        {
            _captureEngine.StartMockCapture();
            _queueManager.Start();
        }
    }

    private void StopBtn_Click(object sender, RoutedEventArgs e)
    {
        _captureEngine.StopCapture();
        _queueManager.Stop();
    }

    private void ClearBtn_Click(object sender, RoutedEventArgs e)
    {
        _packets.Clear();
        _packetCounter = 0;
        _totalBytes = 0;
        _safePackets = 0;
        _threatsDetected = 0;
        _protocolCounts.Clear();
        _ipRowMap.Clear();
        _selectedPacket = null;
        
        PacketDetailTree.Items.Clear();
        HexViewer.Document.Blocks.Clear();
        Md5Text.Text = string.Empty;
        Sha256Text.Text = string.Empty;
        
        UpdateStats();
    }

    private void SaveBtn_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Wireshark PCAPNG (*.pcapng)|*.pcapng|Wireshark PCAP (*.pcap)|*.pcap|All Files (*.*)|*.*",
            DefaultExt = ".pcapng"
        };

        if (dialog.ShowDialog() == true)
        {
            PcapWriter.SavePacketsAuto(dialog.FileName, _packets.ToList());
        }
    }

    private void MockToggle_Checked(object sender, RoutedEventArgs e)
    {
        AppConfig.Instance.MockMode = true;
        MockToggle.Content = "⚡ Mock ON";
    }

    private void MockToggle_Unchecked(object sender, RoutedEventArgs e)
    {
        AppConfig.Instance.MockMode = false;
        MockToggle.Content = "⚡ Mock OFF";
    }

    private void ApiKeysBtn_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ApiSettingsDialog();
        dialog.Owner = this;
        dialog.ShowDialog();
    }

    private void InterfaceCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Handle interface change
    }

    private void CaptureEngine_OnPacketReceived(PacketInfo packet)
    {
        Dispatcher.InvokeAsync(() =>
        {
            try
            {
                ProcessSinglePacket(packet);
                UpdateStats();
            }
            catch { }
        });
    }

    private void CaptureEngine_OnPacketBatchReceived(List<PacketInfo> packets)
    {
        Dispatcher.InvokeAsync(() =>
        {
            try
            {
                foreach (var packet in packets)
                {
                    ProcessSinglePacket(packet);
                }
                UpdateStats();
            }
            catch { }
        });
    }

    private void ProcessSinglePacket(PacketInfo packet)
    {
        packet.No = ++_packetCounter;
        _totalBytes += packet.Length;
        _packets.Add(packet);

        if (!string.IsNullOrEmpty(packet.Protocol))
        {
            if (_protocolCounts.ContainsKey(packet.Protocol))
                _protocolCounts[packet.Protocol]++;
            else
                _protocolCounts[packet.Protocol] = 1;
        }

        EnqueueIpForThreatIntel(packet.Source, _packetCounter - 1);
        EnqueueIpForThreatIntel(packet.Destination, _packetCounter - 1);
    }

    private void EnqueueIpForThreatIntel(string ip, int rowIndex)
    {
        if (string.IsNullOrEmpty(ip) || ip == "127.0.0.1" || ip == "::1" || ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172.16."))
            return;

        if (!_ipRowMap.ContainsKey(ip))
        {
            _ipRowMap[ip] = new List<int>();
            _queueManager.EnqueueIp(ip);
        }
        _ipRowMap[ip].Add(rowIndex);
    }

    private void CaptureEngine_OnStatusChanged(string message)
    {
        bool isCapturing = message.Contains("Started", StringComparison.OrdinalIgnoreCase);
        Dispatcher.Invoke(() =>
        {
            if (isCapturing)
            {
                StatusIndicatorText.Text = "● LIVE CAPTURE";
                StatusIndicatorText.Foreground = (Brush)FindResource("SafeGreenBrush");
                CaptureStatusLabel.Text = $"● Capturing on {InterfaceCombo.SelectedItem}";
                CaptureStatusLabel.Foreground = (Brush)FindResource("SafeGreenBrush");
            }
            else
            {
                StatusIndicatorText.Text = "● IDLE";
                StatusIndicatorText.Foreground = (Brush)FindResource("TextMutedBrush");
                CaptureStatusLabel.Text = "○ Capture stopped";
                CaptureStatusLabel.Foreground = (Brush)FindResource("TextMutedBrush");
            }
            FilterIndicator.Text = string.IsNullOrEmpty(BpfFilterBox.Text) ? "No Filter" : BpfFilterBox.Text;
        });
    }

    private void CaptureEngine_OnErrorOccurred(string error)
    {
        Dispatcher.Invoke(() =>
        {
            MessageBox.Show(error, "Capture Error", MessageBoxButton.OK, MessageBoxImage.Error);
        });
    }

    private void CaptureEngine_OnPermissionError(string message)
    {
        Dispatcher.Invoke(() =>
        {
            MessageBox.Show(message, "Permission/Installation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        });
    }

    private void QueueManager_OnThreatResolved(string ip, ThreatData threat)
    {
        Dispatcher.InvokeAsync(() =>
        {
            try
            {
                if (_ipRowMap.TryGetValue(ip, out var rowIndices))
                {
                    foreach (var index in rowIndices)
                    {
                        if (index >= 0 && index < _packets.Count)
                        {
                            var packet = _packets[index];
                            packet.ThreatData = threat;
                            int vtScore = threat.VtMalicious > 0 ? Math.Min(threat.VtMalicious * 20, 100) : 0;
                            packet.ThreatScore = Math.Max(threat.AbuseScore, vtScore);
                            if (packet.ThreatScore > 0)
                            {
                                _threatsDetected++;
                            }
                            else
                            {
                                _safePackets++;
                            }
                        }
                    }
                    UpdateStats();

                    if (_selectedPacket != null && (_selectedPacket.Source == ip || _selectedPacket.Destination == ip))
                    {
                        BuildLayerTreeItems(_selectedPacket.LayersTree, _selectedPacket);
                    }
                }
            }
            catch { }
        });
    }

    private void QueueManager_OnQueueStatusChanged(int pending, int processing)
    {
        Dispatcher.Invoke(() =>
        {
            QueueStatusText.Text = $"Pending: {pending} | Processing: {processing}";
        });
    }

    private void PacketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PacketGrid.SelectedItem is PacketInfo packet)
        {
            _selectedPacket = packet;
            BuildLayerTreeItems(packet.LayersTree, packet);
            UpdateHexView(packet);
            UpdateStats();
        }
    }

    private void BuildLayerTreeItems(List<LayerNode> layers, PacketInfo? packet)
    {
        PacketDetailTree.Items.Clear();

        if (packet?.ThreatData != null)
        {
            var threat = packet.ThreatData;
            string targetIp = !string.IsNullOrEmpty(threat.Ip) ? threat.Ip : (!string.IsNullOrEmpty(packet.Destination) ? packet.Destination : packet.Source);

            // 1. Threat Intelligence Summary Node
            string nodeTitle = $"Threat Intelligence Summary [IP: {targetIp}] - Abuse: {threat.AbuseScore}%, VT Malicious: {threat.VtMalicious}";
            bool isThreat = packet.ThreatScore > 0 || threat.VtMalicious > 0 || threat.AbuseScore > 20;

            var threatNode = new TreeViewItem 
            { 
                Header = nodeTitle, 
                FontWeight = FontWeights.Bold,
                Foreground = isThreat ? (Brush)FindResource("CriticalRedBrush") : (Brush)FindResource("SafeGreenBrush"),
                IsExpanded = true 
            };

            threatNode.Items.Add(new TreeViewItem { Header = $"AbuseIPDB Score: {threat.AbuseScore}% ({threat.ReportsCount} total reports)" });
            threatNode.Items.Add(new TreeViewItem { Header = $"VirusTotal Detections: {threat.VtMalicious} Malicious, {threat.VtSuspicious} Suspicious" });
            threatNode.Items.Add(new TreeViewItem { Header = $"Geographic Country Code: {(!string.IsNullOrEmpty(threat.Country) ? threat.Country : "N/A")}" });
            threatNode.Items.Add(new TreeViewItem { Header = $"Associated Domain: {(!string.IsNullOrEmpty(threat.Domain) ? threat.Domain : "N/A")}" });
            threatNode.Items.Add(new TreeViewItem { Header = $"Cache Status: {(threat.IsCached ? "In-Memory Cache" : "Live API Lookup")}" });

            PacketDetailTree.Items.Add(threatNode);

            // 2. IPinfo Details & Geolocation Node
            var ipinfoNode = new TreeViewItem 
            { 
                Header = "IPinfo Details & Geolocation", 
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x38, 0xBD, 0xF8)),
                IsExpanded = true 
            };

            ipinfoNode.Items.Add(new TreeViewItem { Header = $"ip: {targetIp}" });
            if (!string.IsNullOrEmpty(threat.IpInfoCity)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"city: {threat.IpInfoCity}" });
            if (!string.IsNullOrEmpty(threat.IpInfoRegion)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"region: {threat.IpInfoRegion}" });
            if (!string.IsNullOrEmpty(threat.IpInfoCountry)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"country: {threat.IpInfoCountry}" });
            if (!string.IsNullOrEmpty(threat.IpInfoLoc)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"loc: {threat.IpInfoLoc}" });
            if (!string.IsNullOrEmpty(threat.IpInfoOrg)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"org: {threat.IpInfoOrg}" });
            if (!string.IsNullOrEmpty(threat.IpInfoPostal)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"postal: {threat.IpInfoPostal}" });
            if (!string.IsNullOrEmpty(threat.IpInfoTimezone)) ipinfoNode.Items.Add(new TreeViewItem { Header = $"timezone: {threat.IpInfoTimezone}" });
            
            ipinfoNode.Items.Add(new TreeViewItem { Header = "Shodan Details: (No Public Ports / Unindexed Host)" });

            PacketDetailTree.Items.Add(ipinfoNode);
        }

        foreach (var layer in layers)
        {
            var item = CreateTreeItem(layer);
            item.IsExpanded = true;
            PacketDetailTree.Items.Add(item);
        }
    }

    private TreeViewItem CreateTreeItem(LayerNode node)
    {
        var item = new TreeViewItem { Header = node.Label, IsExpanded = true };
        foreach (var child in node.Children)
        {
            item.Items.Add(CreateTreeItem(child));
        }
        return item;
    }

    private void UpdateHexView(PacketInfo packet)
    {
        HexViewer.Document.Blocks.Clear();
        
        if (packet.RawBytes == null || packet.RawBytes.Length == 0)
        {
            HexByteCountText.Text = "0 bytes";
            Md5Text.Text = string.Empty;
            Sha256Text.Text = string.Empty;
            return;
        }

        HexByteCountText.Text = $"{packet.RawBytes.Length} bytes";
        Md5Text.Text = packet.PayloadHashMd5;
        Sha256Text.Text = packet.PayloadHashSha256;

        var paragraph = new Paragraph { FontFamily = (FontFamily)FindResource("MonoFont"), FontSize = 12.0 };
        
        for (int i = 0; i < packet.RawBytes.Length; i += 16)
        {
            var offsetRun = new Run($"{i:X4}  ") { Foreground = (Brush)FindResource("AccentCyanBrush") };
            paragraph.Inlines.Add(offsetRun);

            var hexPart = new StringBuilder();
            var asciiPart = new StringBuilder();

            for (int j = 0; j < 16; j++)
            {
                if (i + j < packet.RawBytes.Length)
                {
                    byte b = packet.RawBytes[i + j];
                    hexPart.Append($"{b:x2} ");
                    asciiPart.Append((b >= 32 && b <= 126) ? (char)b : '.');
                }
                else
                {
                    hexPart.Append("   ");
                    asciiPart.Append(' ');
                }

                if (j == 7) hexPart.Append(' ');
            }

            var hexRun = new Run(hexPart.ToString() + " ") { Foreground = Brushes.White };
            var asciiRun = new Run(asciiPart.ToString() + "\n") { Foreground = (Brush)FindResource("AccentCyanBrush") };
            
            paragraph.Inlines.Add(hexRun);
            paragraph.Inlines.Add(asciiRun);
        }

        HexViewer.Document.Blocks.Add(paragraph);
    }

    private void UpdateStats()
    {
        TotalPacketsText.Text = _packetCounter.ToString("N0");
        TotalBytesText.Text = FormatBytes(_totalBytes);
        SafePacketsText.Text = _safePackets.ToString("N0");
        ThreatsDetectedText.Text = _threatsDetected.ToString("N0");
        
        PacketCountLabel.Text = $"Packets: {_packetCounter:N0}";
        ByteCountLabel.Text = $"Bytes: {_totalBytes:N0}";

        if (_selectedPacket != null)
        {
            SelectedPacketSummaryText.Text = $"No. {_selectedPacket.No}: {_selectedPacket.Source} -> {_selectedPacket.Destination} ({_selectedPacket.Protocol})";
        }
        else
        {
            SelectedPacketSummaryText.Text = "None selected";
        }

        var topProtocols = _protocolCounts
            .OrderByDescending(kv => kv.Value)
            .Take(5)
            .Select(kv => new { Key = kv.Key, Value = (kv.Value * 100.0) / _packetCounter })
            .ToList();

        ProtocolBreakdownList.ItemsSource = topProtocols;
    }

    private string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int counter = 0;
        decimal number = bytes;
        while (Math.Round(number / 1024) >= 1)
        {
            number = number / 1024;
            counter++;
        }
        return $"{number:n1} {suffixes[counter]}";
    }

    protected override void OnClosed(EventArgs e)
    {
        _captureEngine?.StopCapture();
        _queueManager?.Stop();
        base.OnClosed(e);
    }
}
