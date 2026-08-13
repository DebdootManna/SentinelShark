using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using SentinelSharkDotNet.Core;
using SentinelSharkDotNet.Models;
using SentinelSharkDotNet.UI.Controls;

namespace SentinelSharkDotNet.UI;

public partial class InterfaceSelectionDialog : Window
{
    public string? SelectedInterface { get; private set; }
    private DispatcherTimer _timer;
    private List<InterfaceInfo> _interfaces = new();
    private Dictionary<string, long> _previousBytes = new();
    private Dictionary<string, SparklineControl> _sparklines = new();

    public class InterfaceInfo
    {
        public string FriendlyName { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string RateDisplay { get; set; } = "0 KB/s";
        public string Id { get; set; } = string.Empty;
    }

    public InterfaceSelectionDialog()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up && 
                         ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .ToList();

        foreach (var ni in networkInterfaces)
        {
            var ipProps = ni.GetIPProperties();
            var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            string ipAddress = ipv4 != null ? ipv4.Address.ToString() : "N/A";

            _interfaces.Add(new InterfaceInfo
            {
                Id = ni.Id,
                FriendlyName = ni.Name,
                IpAddress = ipAddress
            });
            
            _previousBytes[ni.Id] = ni.GetIPv4Statistics().BytesReceived + ni.GetIPv4Statistics().BytesSent;
        }

        InterfacesGrid.ItemsSource = _interfaces;

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(300)
        };
        _timer.Tick += Timer_Tick;
        _timer.Start();
    }
    
    private void OnClosed(object? sender, EventArgs e)
    {
        _timer?.Stop();
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var ni in networkInterfaces)
        {
            if (!_previousBytes.ContainsKey(ni.Id)) continue;
            
            long currentBytes = ni.GetIPv4Statistics().BytesReceived + ni.GetIPv4Statistics().BytesSent;
            long delta = currentBytes - _previousBytes[ni.Id];
            _previousBytes[ni.Id] = currentBytes;

            double kbps = (delta / 1024.0) * (1000.0 / 300.0);

            var info = _interfaces.FirstOrDefault(i => i.Id == ni.Id);
            if (info != null)
            {
                info.RateDisplay = kbps > 1024 ? $"{kbps / 1024.0:F2} MB/s" : $"{kbps:F1} KB/s";
            }

            if (_sparklines.TryGetValue(ni.Id, out var sparkline))
            {
                sparkline.AddValue(kbps);
            }
        }
        
        InterfacesGrid.Items.Refresh();
    }

    private void Sparkline_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is SparklineControl sparkline && sparkline.Tag is InterfaceInfo info)
        {
            _sparklines[info.Id] = sparkline;
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        DragMove();
    }

    private void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (InterfacesGrid.SelectedItem is InterfaceInfo info)
        {
            SelectedInterface = info.Id;
            DialogResult = true;
            Close();
        }
        else
        {
            MessageBox.Show("Please select an interface first.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void InterfacesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        StartBtn_Click(sender, e);
    }
}
