using System;
using System.Windows;

namespace SentinelSharkDotNet;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            MessageBox.Show($"An unhandled exception occurred: {args.ExceptionObject}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        };
    }
}
