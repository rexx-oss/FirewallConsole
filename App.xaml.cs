using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using FirewallConsole.Storage;
using Application = System.Windows.Application;

namespace FirewallConsole;

public partial class App : Application
{
    private const string MutexName = @"Global\FirewallConsole_SingleInstance_Mutex";
    private const string EventName = @"Global\FirewallConsole_SingleInstance_Event";

    private static Mutex? _singleInstanceMutex;
    private static EventWaitHandle? _singleInstanceEvent;
    private static RegisteredWaitHandle? _registeredWait;

    public static IniConfig Config { get; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        // Check for existing running instance
        _singleInstanceMutex = new Mutex(true, MutexName, out bool isFirstInstance);

        if (!isFirstInstance)
        {
            // Another instance is already running. Signal it to restore its window.
            try
            {
                using var waitEvent = EventWaitHandle.OpenExisting(EventName);
                waitEvent.Set();
            }
            catch { }

            // Terminate duplicate process immediately
            Environment.Exit(0);
            return;
        }

        // Primary instance: listen for signals from subsequent launches
        _singleInstanceEvent = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
        _registeredWait = ThreadPool.RegisterWaitForSingleObject(_singleInstanceEvent, (state, timedOut) =>
        {
            Current.Dispatcher.Invoke(() =>
            {
                if (Current.MainWindow is MainWindow win)
                {
                    win.RestoreWindow();
                }
            });
        }, null, -1, false);

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

    protected override void OnExit(ExitEventArgs e)
    {
        _registeredWait?.Unregister(null);
        _singleInstanceEvent?.Dispose();

        if (_singleInstanceMutex != null)
        {
            try
            {
                _singleInstanceMutex.ReleaseMutex();
            }
            catch { }
            _singleInstanceMutex.Dispose();
        }

        base.OnExit(e);
    }
}
