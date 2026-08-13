using System;
using System.Diagnostics;
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
            Debug.WriteLine($"UI Exception handled safely: {args.Exception.Message}");
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            Debug.WriteLine($"Application Exception: {args.ExceptionObject}");
        };
    }
}
