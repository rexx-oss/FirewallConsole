using System.Windows;
using WinFirewallConsole.Storage;

namespace WinFirewallConsole;

public partial class App : Application
{
    public static IniConfig Settings { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var settingsPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.ini");
        Settings.Load(settingsPath);

        string theme = Settings.GetValue("Appearance", "Theme", "Dark");
        SetTheme(theme);
    }

    public static void SetTheme(string theme)
    {
        var dictUri = theme.Equals("Light", StringComparison.OrdinalIgnoreCase)
            ? "Themes/LightTheme.xaml"
            : "Themes/DarkTheme.xaml";

        var resourceDict = new ResourceDictionary { Source = new Uri(dictUri, UriKind.Relative) };
        Current.Resources.MergedDictionaries.Clear();
        Current.Resources.MergedDictionaries.Add(resourceDict);

        Settings.SetValue("Appearance", "Theme", theme);
        Settings.Save(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.ini"));
    }
}
