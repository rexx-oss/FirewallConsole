using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using FirewallConsole.Firewall;
using FirewallConsole.Models;
using FirewallConsole.Monitoring;
using WinForms = System.Windows.Forms;
using Application = System.Windows.Application;
using ContextMenu = System.Windows.Controls.ContextMenu;
using DataGrid = System.Windows.Controls.DataGrid;
using DragEventArgs = System.Windows.DragEventArgs;
using MenuItem = System.Windows.Controls.MenuItem;
using MessageBox = System.Windows.MessageBox;

namespace FirewallConsole;

public partial class MainWindow : Window
{
    private readonly FirewallEngine _engine = new();
    private List<FirewallRuleModel> _allRules = new();
    private readonly ObservableCollection<BlockedConnectionModel> _blockedLogs = new();
    private readonly BlockedConnectionMonitor _monitor = new();
    private bool _isWhitelistMode = true;
    private WinForms.NotifyIcon? _notifyIcon;
    private ContextMenu? _trayContextMenu;
    private MenuItem? _trayModeMenuItem;
    private readonly DispatcherTimer _watchdogTimer = new();
    private bool _isClosingFromTray = false;

    [DllImport("psapi.dll")]
    private static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    public static void TrimWorkingSet()
    {
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        GC.WaitForPendingFinalizers();
        try
        {
            using var proc = Process.GetCurrentProcess();
            EmptyWorkingSet(proc.Handle);
        }
        catch { }
    }

    public MainWindow()
    {
        InitializeComponent();
        InitializeTrayAndIcons();
        BlockedGrid.ItemsSource = _blockedLogs;
        _monitor.BlockedConnectionReceived += Monitor_BlockedConnectionReceived;

        SourceInitialized += (s, e) => ApplyTitleBarTheme();
        Loaded += MainWindow_Loaded;

        _watchdogTimer.Interval = TimeSpan.FromSeconds(15);
        _watchdogTimer.Tick += async (s, e) =>
        {
            if (_isWhitelistMode)
            {
                var (disabled, _) = await Task.Run(() => _engine.SetOperatingMode(true));
                if (disabled > 0 && IsVisible)
                {
                    await ReloadRulesAsync();
                }
            }
        };
    }

    private void ApplyTitleBarTheme()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;

        string theme = App.Config.GetValue("Settings", "Theme", "Light");
        int useDark = theme.Equals("Dark", StringComparison.OrdinalIgnoreCase) ? 1 : 0;

        if (DwmSetWindowAttribute(hwnd, 20, ref useDark, sizeof(int)) != 0)
        {
            DwmSetWindowAttribute(hwnd, 19, ref useDark, sizeof(int));
        }
    }

    private void Monitor_BlockedConnectionReceived(BlockedConnectionModel item)
    {
        Dispatcher.Invoke(() =>
        {
            _blockedLogs.Insert(0, item);
            if (_blockedLogs.Count > 300)
            {
                _blockedLogs.RemoveAt(_blockedLogs.Count - 1);
            }
        });
    }

    private void InitializeTrayAndIcons()
    {
        _notifyIcon = new WinForms.NotifyIcon
        {
            Text = "Firewall Console",
            Visible = true
        };

        try
        {
            System.Drawing.Bitmap? bmp = null;
            var resUri = new Uri("pack://application:,,,/icon.png", UriKind.Absolute);
            var streamInfo = Application.GetResourceStream(resUri);

            if (streamInfo != null)
            {
                using var mem = new MemoryStream();
                streamInfo.Stream.CopyTo(mem);
                mem.Position = 0;
                bmp = new System.Drawing.Bitmap(mem);
                mem.Position = 0;
                this.Icon = BitmapFrame.Create(mem, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            }
            else
            {
                var loosePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.png");
                if (File.Exists(loosePath))
                {
                    bmp = new System.Drawing.Bitmap(loosePath);
                    this.Icon = new BitmapImage(new Uri(loosePath, UriKind.Absolute));
                }
            }

            if (bmp != null)
            {
                IntPtr hIcon = bmp.GetHicon();
                _notifyIcon.Icon = System.Drawing.Icon.FromHandle(hIcon);
            }
            else
            {
                _notifyIcon.Icon = System.Drawing.SystemIcons.Application;
            }
        }
        catch
        {
            _notifyIcon.Icon = System.Drawing.SystemIcons.Application;
        }

        // Native WPF Modern ContextMenu
        _trayContextMenu = new ContextMenu
        {
            Placement = PlacementMode.MousePoint
        };

        var openItem = new MenuItem { Header = "Open Console" };
        openItem.Click += (s, e) => RestoreWindow();

        _trayModeMenuItem = new MenuItem { Header = GetModeText() };
        _trayModeMenuItem.Click += (s, e) => ToggleMode();

        var sep = new Separator();

        var exitItem = new MenuItem { Header = "Exit" };
        exitItem.Click += (s, e) => ExitApp();

        _trayContextMenu.Items.Add(openItem);
        _trayContextMenu.Items.Add(_trayModeMenuItem);
        _trayContextMenu.Items.Add(sep);
        _trayContextMenu.Items.Add(exitItem);

        _notifyIcon.MouseUp += NotifyIcon_MouseUp;
        _notifyIcon.DoubleClick += (s, e) => Dispatcher.Invoke(RestoreWindow);
    }

    private void NotifyIcon_MouseUp(object? sender, WinForms.MouseEventArgs e)
    {
        if (e.Button == WinForms.MouseButtons.Right && _trayContextMenu != null)
        {
            Dispatcher.Invoke(() =>
            {
                var hwnd = new WindowInteropHelper(this).Handle;
                if (hwnd != IntPtr.Zero)
                {
                    SetForegroundWindow(hwnd);
                }
                _trayContextMenu.IsOpen = true;
            });
        }
    }

    private string GetModeText() =>
        _isWhitelistMode ? "Mode: Whitelist (Strict)" : "Mode: Blacklist (Permissive)";

    private void RestoreWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        ShowInTaskbar = true;
        Activate();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            string mode = App.Config.GetValue("Settings", "Mode", "Whitelist");
            _isWhitelistMode = mode.Equals("Whitelist", StringComparison.OrdinalIgnoreCase);
            UpdateModeButtonLabel();

            bool startOnLogin = bool.TryParse(App.Config.GetValue("Settings", "StartOnLogin", "false"), out bool sol) && sol;
            ChkStartOnLogin.IsChecked = startOnLogin;

            StatusLabel.Text = "Synchronizing backup rules from firecon.ini...";
            int restored = await Task.Run(() => _engine.SyncStoredRulesFromConfig());

            StatusLabel.Text = "Applying configured firewall policy...";
            var (affected, retained) = await Task.Run(() => _engine.SetOperatingMode(_isWhitelistMode));

            await ReloadRulesAsync();
            _watchdogTimer.Start();

            StatusLabel.Text = _isWhitelistMode
                ? $"Whitelist Active: Restored {restored} rules. Suppressed {affected} unapproved rules."
                : $"Blacklist Active: Restored {restored} rules. Operating permissively.";

            TrimWorkingSet();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Startup error: {ex.Message}\n\nEnsure this application is run as Administrator.",
                            "Initialization Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task ReloadRulesAsync()
    {
        _allRules = await Task.Run(() => _engine.GetAllRules());
        ApplyFilter();
        StatsLabel.Text = $"Total Outbound: {_allRules.Count(r => r.Direction == "Outbound")} | Total Inbound: {_allRules.Count(r => r.Direction == "Inbound")}";
        TrimWorkingSet();
    }

    private void ApplyFilter()
    {
        var filter = SearchBox.Text.Trim();
        var currentTab = (RulesTabControl.SelectedItem as TabItem)?.Header?.ToString() ?? "Outbound Rules";

        if (currentTab.Contains("Blocked")) return;

        bool isOutbound = currentTab.Contains("Outbound");
        var targetList = _allRules.Where(r => isOutbound ? r.Direction == "Outbound" : r.Direction == "Inbound");

        if (!string.IsNullOrWhiteSpace(filter))
        {
            targetList = targetList.Where(r =>
                r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.ApplicationName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.LocalPorts.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        var result = targetList.ToList();
        if (isOutbound) OutboundGrid.ItemsSource = result;
        else InboundGrid.ItemsSource = result;
    }

    private DataGrid GetActiveGrid() =>
        RulesTabControl.SelectedIndex == 0 ? OutboundGrid : InboundGrid;

    private List<FirewallRuleModel> GetSelectedRules() =>
        GetActiveGrid().SelectedItems.Cast<FirewallRuleModel>().ToList();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void RulesTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source is TabControl) ApplyFilter();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        StatusLabel.Text = "Refreshing rules...";
        await ReloadRulesAsync();
        StatusLabel.Text = "Rules updated.";
    }

    private void ModeToggle_Click(object sender, RoutedEventArgs e) => ToggleMode();

    private async void ToggleMode()
    {
        _isWhitelistMode = !_isWhitelistMode;
        UpdateModeButtonLabel();

        StatusLabel.Text = _isWhitelistMode
            ? "Switching to Whitelist: Blocking unapproved outbound traffic..."
            : "Switching to Blacklist: Allowing outbound traffic and restoring rules...";

        var (affected, retained) = await Task.Run(() => _engine.SetOperatingMode(_isWhitelistMode));
        await ReloadRulesAsync();

        StatusLabel.Text = _isWhitelistMode
            ? $"Whitelist Mode Active. Default Outbound: Blocked. Suppressed {affected} rules."
            : $"Blacklist Mode Active. Default Outbound: Allowed. Restored {affected} rules.";
    }

    private void UpdateModeButtonLabel()
    {
        string modeLabel = GetModeText();
        ModeToggleButton.Content = modeLabel;
        if (_trayModeMenuItem != null)
        {
            _trayModeMenuItem.Header = modeLabel;
        }
        if (_notifyIcon != null)
        {
            _notifyIcon.Text = $"Firewall Console - {(_isWhitelistMode ? "Whitelist" : "Blacklist")}";
        }
    }

    private void ChkStartOnLogin_Changed(object sender, RoutedEventArgs e)
    {
        bool isChecked = ChkStartOnLogin.IsChecked ?? false;
        App.Config.SetValue("Settings", "StartOnLogin", isChecked.ToString().ToLowerInvariant());
        App.Config.Save(_engine.ConfigPath);

        Task.Run(() => SetStartupOnLogin(isChecked));
    }

    private static void SetStartupOnLogin(bool enable)
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName 
                             ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firecon.exe");
            const string taskName = "FirewallConsole_Startup";

            if (enable)
            {
                var psi = new ProcessStartInfo("schtasks.exe", $"/Create /TN \"{taskName}\" /TR \"\\\"{exePath}\\\" --startup\" /SC ONLOGON /RL HIGHEST /F")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(2000);
            }
            else
            {
                var psi = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(2000);
            }
        }
        catch { }
    }

    private void NewRule_Click(object sender, RoutedEventArgs e) => OpenRuleDialog();

    private void EditSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count > 0)
        {
            OpenEditRuleDialog(selected[0]);
        }
    }

    private void Grid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (GetSelectedRules() is { Count: > 0 } list)
        {
            OpenEditRuleDialog(list[0]);
        }
    }

    private void BlockedGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (BlockedGrid.SelectedItem is BlockedConnectionModel blocked)
        {
            if (!string.IsNullOrWhiteSpace(blocked.ApplicationName) && blocked.ApplicationName != "Unknown")
            {
                OpenRuleDialog(blocked.ApplicationName, blocked.Direction, blocked.Protocol);
            }
        }
    }

    private async void OpenEditRuleDialog(FirewallRuleModel ruleToEdit)
    {
        var dialog = new RuleDialog(ruleToEdit) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.CreatedRule != null)
        {
            StatusLabel.Text = $"Updating rule '{dialog.CreatedRule.Name}'...";
            await Task.Run(() => _engine.UpdateRule(ruleToEdit, dialog.CreatedRule));
            await ReloadRulesAsync();
            StatusLabel.Text = $"Rule '{dialog.CreatedRule.Name}' updated.";
        }
    }

    private async void OpenRuleDialog(string? prefilledPath = null, string? direction = null, string? protocol = null)
    {
        var dialog = new RuleDialog(prefilledPath, direction, protocol) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.CreatedRule != null)
        {
            StatusLabel.Text = $"Creating rule '{dialog.CreatedRule.Name}'...";
            await Task.Run(() => _engine.AddRule(dialog.CreatedRule));
            await ReloadRulesAsync();
            StatusLabel.Text = $"Rule '{dialog.CreatedRule.Name}' created.";
        }
    }

    private async void Approve_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        StatusLabel.Text = $"Approving {selected.Count} rule(s)...";
        await Task.Run(() =>
        {
            foreach (var r in selected)
            {
                _engine.ApproveRule(r);
                _engine.SetRuleEnabled(r, true);
            }
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Approved and enabled {selected.Count} rule(s).";
    }

    private async void Revoke_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        StatusLabel.Text = $"Revoking {selected.Count} rule(s)...";
        await Task.Run(() =>
        {
            foreach (var r in selected)
            {
                _engine.RevokeRule(r);
            }
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Revoked {selected.Count} rule(s).";
    }

    private async void ToggleEnable_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var r in selected)
            {
                _engine.SetRuleEnabled(r, !r.Enabled);
            }
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Toggled enabled state for {selected.Count} rule(s).";
    }

    private async void ToggleAction_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var r in selected) _engine.ToggleRuleAction(r);
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Toggled action for {selected.Count} rule(s).";
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        var res = MessageBox.Show($"Permanently delete {selected.Count} rule(s)?", "Confirm Delete",
                                  MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (res == MessageBoxResult.Yes)
        {
            StatusLabel.Text = $"Deleting {selected.Count} rule(s)...";
            await Task.Run(() =>
            {
                foreach (var r in selected) _engine.DeleteRule(r);
            });
            await ReloadRulesAsync();
            StatusLabel.Text = $"Deleted {selected.Count} rule(s).";
        }
    }

    private void ToggleLogging_Click(object sender, RoutedEventArgs e)
    {
        if (_monitor.IsRunning)
        {
            _monitor.Stop();
            BtnToggleLogging.Content = "Start Logging";
            BtnToggleLogging.Background = (System.Windows.Media.Brush)FindResource("SuccessBrush");
            LoggingStatusText.Text = "Logging stopped. Monitoring paused.";
            TrimWorkingSet();
        }
        else
        {
            _monitor.Start();
            BtnToggleLogging.Content = "Stop Logging";
            BtnToggleLogging.Background = (System.Windows.Media.Brush)FindResource("DangerBrush");
            LoggingStatusText.Text = "Active: Monitoring blocked connection events. Double-click row to create rule.";
        }
    }

    private void ClearBlockedLog_Click(object sender, RoutedEventArgs e)
    {
        _blockedLogs.Clear();
        TrimWorkingSet();
    }

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var current = App.Config.GetValue("Settings", "Theme", "Light");
        var next = current.Equals("Light", StringComparison.OrdinalIgnoreCase) ? "Dark" : "Light";
        App.SetTheme(next);
        ApplyTitleBarTheme();
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(System.Windows.DataFormats.FileDrop);
            if (files != null && files.Length > 0 && files[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                e.Effects = System.Windows.DragDropEffects.Copy;
                e.Handled = true;
                return;
            }
        }
        e.Effects = System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(System.Windows.DataFormats.FileDrop);
            if (files != null && files.Length > 0 && files[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                OpenRuleDialog(files[0]);
            }
        }
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_isClosingFromTray)
        {
            e.Cancel = true;
            Hide();
            ShowInTaskbar = false;
            TrimWorkingSet();
        }
        else
        {
            _watchdogTimer.Stop();
            _monitor.Dispose();
            _notifyIcon?.Dispose();
        }
    }

    private void ExitApp()
    {
        _isClosingFromTray = true;
        Close();
        Application.Current.Shutdown();
    }
}
