using System;
using System.IO;
using System.Windows;
using FirewallConsole.Storage;

namespace FirewallConsole;

public partial class App : Application
{
    public static IniConfig Settings { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            var ex = args.ExceptionObject as Exception;
            MessageBox.Show($"Fatal Application Error:\n{ex?.Message}\n\nStack:\n{ex?.StackTrace}", 
                            "Fatal Exception", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        base.OnStartup(e);

        var settingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.ini");
        Settings.Load(settingsPath);

        string theme = Settings.GetValue("Appearance", "Theme", "Light");
        SetTheme(theme);
    }

    public static void SetTheme(string theme)
    {
        var dictUri = theme.Equals("Dark", StringComparison.OrdinalIgnoreCase)
            ? "Themes/DarkTheme.xaml"
            : "Themes/LightTheme.xaml";

        var resourceDict = new ResourceDictionary { Source = new Uri(dictUri, UriKind.Relative) };
        Current.Resources.MergedDictionaries.Clear();
        Current.Resources.MergedDictionaries.Add(resourceDict);

        Settings.SetValue("Appearance", "Theme", theme);
        Settings.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.ini"));
    }
}
