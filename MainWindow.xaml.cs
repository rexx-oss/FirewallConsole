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
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using FirewallConsole.Firewall;
using FirewallConsole.Models;
using FirewallConsole.Monitoring;
using WinForms = System.Windows.Forms;
using Application = System.Windows.Application;
using DataGrid = System.Windows.Controls.DataGrid;
using DragEventArgs = System.Windows.DragEventArgs;
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
    private WinForms.ContextMenuStrip? _trayMenu;
    private WinForms.ToolStripMenuItem? _trayModeMenuItem;
    private readonly DispatcherTimer _watchdogTimer = new();
    private bool _isClosingFromTray = false;

    [DllImport("psapi.dll")]
    private static extern bool EmptyWorkingSet(IntPtr hProcess);

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

        _trayMenu = new WinForms.ContextMenuStrip();
        _trayMenu.Font = new System.Drawing.Font("Segoe UI", 9f);

        var openItem = new WinForms.ToolStripMenuItem("Open Console", null, (s, e) => RestoreWindow());
        _trayModeMenuItem = new WinForms.ToolStripMenuItem(GetModeText(), null, (s, e) => Dispatcher.Invoke(ToggleMode));
        var exitItem = new WinForms.ToolStripMenuItem("Exit", null, (s, e) => Dispatcher.Invoke(ExitApp));

        _trayMenu.Items.Add(openItem);
        _trayMenu.Items.Add(_trayModeMenuItem);
        _trayMenu.Items.Add(new WinForms.ToolStripSeparator());
        _trayMenu.Items.Add(exitItem);

        UpdateTrayMenuTheme();

        _notifyIcon.ContextMenuStrip = _trayMenu;
        _notifyIcon.DoubleClick += (s, e) => Dispatcher.Invoke(RestoreWindow);
    }

    private string GetModeText() =>
        _isWhitelistMode ? "Mode: Whitelist (Strict)" : "Mode: Blacklist (Permissive)";

    private void UpdateTrayMenuTheme()
    {
        if (_trayMenu == null) return;
        var theme = App.Config.GetValue("Settings", "Theme", "Light");
        bool isDark = theme.Equals("Dark", StringComparison.OrdinalIgnoreCase);
        _trayMenu.Renderer = new ModernMenuRenderer(isDark);
    }

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
            _trayModeMenuItem.Text = modeLabel;
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
        UpdateTrayMenuTheme();
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
            // Close button "X" minimizes directly to the system tray
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

/// <summary>
/// Custom renderer to match the Tray Context Menu styling directly to Dark/Light themes.
/// Fully qualifies all GDI+ types to eliminate ambiguous collisions with WPF types.
/// </summary>
public class ModernMenuRenderer : WinForms.ToolStripProfessionalRenderer
{
    private readonly bool _isDark;

    public ModernMenuRenderer(bool isDark) : base(new CustomColorTable(isDark))
    {
        _isDark = isDark;
    }

    protected override void OnRenderMenuItemBackground(WinForms.ToolStripItemRenderEventArgs e)
    {
        var g = e.Graphics;
        var rect = new System.Drawing.Rectangle(System.Drawing.Point.Empty, e.Item.Size);

        if (e.Item.Selected)
        {
            var hoverColor = _isDark ? System.Drawing.Color.FromArgb(42, 42, 48) : System.Drawing.Color.FromArgb(229, 231, 235);
            using var b = new System.Drawing.SolidBrush(hoverColor);
            g.FillRectangle(b, rect);
        }
        else
        {
            var bgColor = _isDark ? System.Drawing.Color.FromArgb(30, 30, 34) : System.Drawing.Color.FromArgb(255, 255, 255);
            using var b = new System.Drawing.SolidBrush(bgColor);
            g.FillRectangle(b, rect);
        }
    }

    protected override void OnRenderItemText(WinForms.ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = _isDark ? System.Drawing.Color.FromArgb(244, 244, 246) : System.Drawing.Color.FromArgb(17, 24, 39);
        base.OnRenderItemText(e);
    }

    protected override void OnRenderSeparator(WinForms.ToolStripSeparatorRenderEventArgs e)
    {
        var sepColor = _isDark ? System.Drawing.Color.FromArgb(51, 51, 56) : System.Drawing.Color.FromArgb(209, 213, 219);
        using var pen = new System.Drawing.Pen(sepColor);
        int y = e.Item.Height / 2;
        e.Graphics.DrawLine(pen, 4, y, e.Item.Width - 4, y);
    }

    private class CustomColorTable : WinForms.ProfessionalColorTable
    {
        private readonly bool _dark;
        public CustomColorTable(bool dark) => _dark = dark;

        public override System.Drawing.Color ToolStripDropDownBackground => _dark ? System.Drawing.Color.FromArgb(30, 30, 34) : System.Drawing.Color.FromArgb(255, 255, 255);
        public override System.Drawing.Color MenuBorder => _dark ? System.Drawing.Color.FromArgb(51, 51, 56) : System.Drawing.Color.FromArgb(209, 213, 219);
    }
}
