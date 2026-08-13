using System.Windows;
using System.Windows.Input;
using SentinelSharkDotNet.Core;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.UI;

public partial class ApiSettingsDialog : Window
{
    public ApiSettingsDialog()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        var config = AppConfig.Instance;
        if (config != null)
        {
            TxtAbuseIPDB.Password = config.AbuseIpDbApiKey;
            TxtVirusTotal.Password = config.VirusTotalApiKey;
            TxtIPinfo.Password = config.IpInfoApiKey;
            TxtShodan.Password = config.ShodanApiKey;
            TxtCacheTTL.Text = config.CacheTtlHours.ToString();
            TxtMaxRequests.Text = config.MaxRequestsPerMinute.ToString();
            ChkMockMode.IsChecked = config.MockMode;
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        DragMove();
    }

    private void SaveBtn_Click(object sender, RoutedEventArgs e)
    {
        var config = AppConfig.Instance;
        if (config != null)
        {
            config.AbuseIpDbApiKey = TxtAbuseIPDB.Password;
            config.VirusTotalApiKey = TxtVirusTotal.Password;
            config.IpInfoApiKey = TxtIPinfo.Password;
            config.ShodanApiKey = TxtShodan.Password;
            
            if (int.TryParse(TxtCacheTTL.Text, out int ttl))
            {
                config.CacheTtlHours = ttl;
            }
            if (int.TryParse(TxtMaxRequests.Text, out int maxReq))
            {
                config.MaxRequestsPerMinute = maxReq;
            }
            
            config.MockMode = ChkMockMode.IsChecked ?? false;
            
            config.Save();
        }
        
        DialogResult = true;
        Close();
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
