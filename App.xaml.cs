using System;
using System.IO;
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
            System.Windows.MessageBox.Show($"Fatal Application Error:\n{ex?.Message}\n\nStack:\n{ex?.StackTrace}", 
                                           "Fatal Exception", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        base.OnStartup(e);

        var iniPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firecon.ini");
        Config.Load(iniPath);

        string theme = Config.GetValue("Settings", "Theme", "Light");
        SetTheme(theme);

        var mainWindow = new MainWindow();
        bool startMinimized = bool.TryParse(Config.GetValue("Settings", "StartMinimized", "false"), out bool sm) && sm;

        if (startMinimized)
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
