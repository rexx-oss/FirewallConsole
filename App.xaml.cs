using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using FirewallConsole.Storage;
using Application = System.Windows.Application;

namespace FirewallConsole;

public partial class App : Application
{
    public static IniConfig Config { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            var ex = args.ExceptionObject as Exception;
            var sb = new StringBuilder();
            sb.AppendLine($"Fatal Application Error:\n{ex?.Message}\n");

            var inner = ex?.InnerException;
            while (inner != null)
            {
                sb.AppendLine($"Inner Cause:\n{inner.Message}\n");
                inner = inner.InnerException;
            }

            sb.AppendLine($"Stack Trace:\n{ex?.StackTrace}");
            System.Windows.MessageBox.Show(sb.ToString(), "Fatal Exception", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        base.OnStartup(e);

        var iniPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firecon.ini");
        Config.Load(iniPath);

        string theme = Config.GetValue("Settings", "Theme", "Light");
        SetTheme(theme);

        var mainWindow = new MainWindow();
        bool isStartupLaunch = e.Args.Contains("--startup", StringComparer.OrdinalIgnoreCase);

        if (isStartupLaunch)
        {
            mainWindow.WindowState = WindowState.Minimized;
            mainWindow.ShowInTaskbar = false;
            mainWindow.Hide();
        }
        else
        {
            mainWindow.Show();
        }
    }

    public static void SetTheme(string theme)
    {
        var dictUri = theme.Equals("Dark", StringComparison.OrdinalIgnoreCase)
            ? "Themes/DarkTheme.xaml"
            : "Themes/LightTheme.xaml";

        var resourceDict = new ResourceDictionary { Source = new Uri(dictUri, UriKind.Relative) };
        Current.Resources.MergedDictionaries.Clear();
        Current.Resources.MergedDictionaries.Add(resourceDict);

        Config.SetValue("Settings", "Theme", theme);
        Config.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firecon.ini"));
    }
}
