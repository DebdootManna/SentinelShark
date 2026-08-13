using System;
using System.Windows;

namespace SentinelSharkDotNet;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        this.DispatcherUnhandledException += (s, args) =>
        {
            args.Handled = true;
            MessageBox.Show($"UI Exception caught safely: {args.Exception.Message}", "SentinelShark Exception Handler", MessageBoxButton.OK, MessageBoxImage.Warning);
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            MessageBox.Show($"Application Exception: {args.ExceptionObject}", "SentinelShark Error", MessageBoxButton.OK, MessageBoxImage.Error);
        };
    }
}
