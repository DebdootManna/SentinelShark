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
        
        // Mock showing dialog since InterfaceSelectionDialog is not implemented in this snippet
        // var dialog = new InterfaceSelectionDialog();
        // if (dialog.ShowDialog() == true) { ... }
    }

    private void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (InterfaceCombo.SelectedItem is string selectedInterface)
        {
            string filter = BpfFilterBox.Text;
            _captureEngine.StartCapture(selectedInterface, filter);
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
            Filter = "PCAP Files (*.pcap)|*.pcap|All Files (*.*)|*.*",
            DefaultExt = ".pcap"
        };

        if (dialog.ShowDialog() == true)
        {
            PcapWriter.SavePcapFile(dialog.FileName, _packets.ToList());
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
        // var dialog = new ApiSettingsDialog();
        // dialog.ShowDialog();
    }

    private void InterfaceCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Handle interface change
    }

    private void CaptureEngine_OnPacketReceived(PacketInfo packet)
    {
        Dispatcher.Invoke(() =>
        {
            ProcessSinglePacket(packet);
            UpdateStats();
        });
    }

    private void CaptureEngine_OnPacketBatchReceived(List<PacketInfo> packets)
    {
        Dispatcher.Invoke(() =>
        {
            foreach (var packet in packets)
            {
                ProcessSinglePacket(packet);
            }
            UpdateStats();
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
        Dispatcher.Invoke(() =>
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
                PacketGrid.Items.Refresh();

                if (_selectedPacket != null && (_selectedPacket.Source == ip || _selectedPacket.Destination == ip))
                {
                    BuildLayerTreeItems(_selectedPacket.LayersTree, _selectedPacket);
                }
            }
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
            bool isThreat = packet.ThreatScore > 0;
            var threatNode = new TreeViewItem { Header = $"Threat Intel Summary - {(isThreat ? "THREAT" : "SAFE")}", FontWeight = FontWeights.Bold };
            threatNode.Foreground = isThreat ? (Brush)FindResource("CriticalRedBrush") : (Brush)FindResource("SafeGreenBrush");
            
            string description = $"{threat.IpInfoOrg} {threat.Country} {(threat.Domain != null ? "- " + threat.Domain : "")}".Trim();

            threatNode.Items.Add(new TreeViewItem { Header = $"IP: {threat.Ip}" });
            threatNode.Items.Add(new TreeViewItem { Header = $"Score: {packet.ThreatScore}/100" });
            threatNode.Items.Add(new TreeViewItem { Header = $"Description: {description}" });
            
            PacketDetailTree.Items.Add(threatNode);
        }

        foreach (var layer in layers)
        {
            PacketDetailTree.Items.Add(CreateTreeItem(layer));
        }
    }

    private TreeViewItem CreateTreeItem(LayerNode node)
    {
        var item = new TreeViewItem { Header = node.Label };
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

        var paragraph = new Paragraph();
        
        for (int i = 0; i < packet.RawBytes.Length; i += 16)
        {
            var offsetRun = new Run($"{i:X4}  ") { Foreground = (Brush)FindResource("AccentCyanBrush") };
            paragraph.Inlines.Add(offsetRun);

            string hexPart = "";
            string asciiPart = "";

            for (int j = 0; j < 16; j++)
            {
                if (i + j < packet.RawBytes.Length)
                {
                    byte b = packet.RawBytes[i + j];
                    hexPart += $"{b:X2} ";
                    asciiPart += (b >= 32 && b <= 126) ? (char)b : '.';
                }
                else
                {
                    hexPart += "   ";
                    asciiPart += " ";
                }

                if (j == 7) hexPart += " ";
            }

            var hexRun = new Run(hexPart + "  ") { Foreground = Brushes.White };
            var asciiRun = new Run(asciiPart + "\n") { Foreground = (Brush)FindResource("TextMutedBrush") };
            
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
