using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
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
    private DispatcherTimer? _timer;
    private List<InterfaceInfo> _interfaces = new();
    private Dictionary<string, long> _previousBytes = new();
    private Dictionary<string, SparklineControl> _sparklines = new();

    public class InterfaceInfo : INotifyPropertyChanged
    {
        private string _rateDisplay = "0 KB/s";

        public string FriendlyName { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string Id { get; set; } = string.Empty;
        public string Status { get; set; } = "UP";

        public string RateDisplay
        {
            get => _rateDisplay;
            set
            {
                if (_rateDisplay != value)
                {
                    _rateDisplay = value;
                    OnPropertyChanged();
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public InterfaceSelectionDialog()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces().ToList();

            foreach (var ni in networkInterfaces)
            {
                string ipAddress = "N/A";
                try
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (ipv4 != null) ipAddress = ipv4.Address.ToString();
                }
                catch { }

                string statusStr = "UP";
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    statusStr = "LOOPBACK";
                }
                else if (ni.OperationalStatus != OperationalStatus.Up)
                {
                    statusStr = "DOWN";
                }

                _interfaces.Add(new InterfaceInfo
                {
                    Id = ni.Id,
                    FriendlyName = ni.Name,
                    IpAddress = ipAddress,
                    Status = statusStr
                });
                
                try
                {
                    var stats = ni.GetIPStatistics();
                    _previousBytes[ni.Id] = stats.BytesReceived + stats.BytesSent;
                }
                catch
                {
                    _previousBytes[ni.Id] = 0;
                }
            }

            InterfacesGrid.ItemsSource = _interfaces;
            if (_interfaces.Count > 0)
            {
                InterfacesGrid.SelectedIndex = 0;
            }

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(300)
            };
            _timer.Tick += Timer_Tick;
            _timer.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error enumerating network interfaces: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
    
    private void OnClosed(object? sender, EventArgs e)
    {
        _timer?.Stop();
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in networkInterfaces)
            {
                if (!_previousBytes.ContainsKey(ni.Id)) continue;
                
                long currentBytes = 0;
                try
                {
                    var stats = ni.GetIPStatistics();
                    currentBytes = stats.BytesReceived + stats.BytesSent;
                }
                catch { continue; }

                long delta = currentBytes - _previousBytes[ni.Id];
                _previousBytes[ni.Id] = currentBytes;

                double kbps = Math.Max(0, (delta / 1024.0) * (1000.0 / 300.0));

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
        }
        catch { }
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
        try
        {
            DragMove();
        }
        catch { }
    }

    private void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (InterfacesGrid.SelectedItem is InterfaceInfo info)
        {
            SelectedInterface = info.FriendlyName;
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
