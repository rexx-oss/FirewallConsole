using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using FirewallConsole.Firewall;
using FirewallConsole.Models;
using FirewallConsole.Monitoring;
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
    private System.Windows.Forms.NotifyIcon? _notifyIcon;
    private readonly DispatcherTimer _watchdogTimer = new();
    private bool _isClosingFromTray = false;

    public MainWindow()
    {
        InitializeComponent();
        InitializeTrayAndIcons();
        BlockedGrid.ItemsSource = _blockedLogs;
        _monitor.BlockedConnectionReceived += Monitor_BlockedConnectionReceived;

        Loaded += MainWindow_Loaded;

        _watchdogTimer.Interval = TimeSpan.FromSeconds(10);
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
            if (_blockedLogs.Count > 500)
            {
                _blockedLogs.RemoveAt(_blockedLogs.Count - 1);
            }
        });
    }

    private void InitializeTrayAndIcons()
    {
        _notifyIcon = new System.Windows.Forms.NotifyIcon
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

        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Open Console", null, (s, e) => RestoreWindow()));
        menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Toggle Mode", null, (s, e) => Dispatcher.Invoke(ToggleMode)));
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add(new System.Windows.Forms.ToolStripMenuItem("Exit", null, (s, e) => Dispatcher.Invoke(ExitApp)));

        _notifyIcon.ContextMenuStrip = menu;
        _notifyIcon.DoubleClick += (s, e) => Dispatcher.Invoke(RestoreWindow);
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

            bool startMinimized = bool.TryParse(App.Config.GetValue("Settings", "StartMinimized", "false"), out bool sm) && sm;
            ChkStartMinimized.IsChecked = startMinimized;

            StatusLabel.Text = "Synchronizing backup rules from firecon.ini...";
            int restored = await Task.Run(() => _engine.SyncStoredRulesFromConfig());

            StatusLabel.Text = "Applying configured firewall policy...";
            var (affected, retained) = await Task.Run(() => _engine.SetOperatingMode(_isWhitelistMode));

            await ReloadRulesAsync();
            _watchdogTimer.Start();

            StatusLabel.Text = _isWhitelistMode
                ? $"Whitelist Active: Restored {restored} rules. Suppressed {affected} unapproved rules."
                : $"Blacklist Active: Restored {restored} rules. Operating permissively.";
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

        if (_isWhitelistMode)
        {
            MessageBox.Show($"Whitelist Mode Active!\n\nDefault Outbound: BLOCKED\nSuppressed allow rules: {affected}\nRetained valid rules: {retained}",
                            "Whitelist Engaged", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show($"Blacklist Mode Active!\n\nDefault Outbound: ALLOWED\nRestored rules: {affected}",
                            "Blacklist Engaged", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void UpdateModeButtonLabel()
    {
        ModeToggleButton.Content = _isWhitelistMode ? "🛡 Mode: Whitelist (Strict)" : "🔓 Mode: Blacklist (Permissive)";
        if (_notifyIcon != null)
        {
            _notifyIcon.Text = $"Firewall Console - {(_isWhitelistMode ? "Whitelist" : "Blacklist")}";
        }
    }

    private void ChkStartMinimized_Changed(object sender, RoutedEventArgs e)
    {
        bool isChecked = ChkStartMinimized.IsChecked ?? false;
        App.Config.SetValue("Settings", "StartMinimized", isChecked.ToString().ToLowerInvariant());
        App.Config.Save(_engine.ConfigPath);
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

    private async void OpenRuleDialog(string? prefilledPath = null)
    {
        var dialog = new RuleDialog(prefilledPath) { Owner = this };
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

    private async void Enable_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var r in selected) _engine.SetRuleEnabled(r, true);
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Enabled {selected.Count} rule(s).";
    }

    private async void Disable_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var r in selected) _engine.SetRuleEnabled(r, false);
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Disabled {selected.Count} rule(s).";
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
            BtnToggleLogging.Content = "▶ Start Logging";
            BtnToggleLogging.Background = (System.Windows.Media.Brush)FindResource("SuccessBrush");
            LoggingStatusText.Text = "Logging stopped. Monitoring paused.";
        }
        else
        {
            _monitor.Start();
            BtnToggleLogging.Content = "⏹ Stop Logging";
            BtnToggleLogging.Background = (System.Windows.Media.Brush)FindResource("DangerBrush");
            LoggingStatusText.Text = "Active: Monitoring blocked connection events in real time...";
        }
    }

    private void ClearBlockedLog_Click(object sender, RoutedEventArgs e) => _blockedLogs.Clear();

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var current = App.Config.GetValue("Settings", "Theme", "Light");
        var next = current.Equals("Light", StringComparison.OrdinalIgnoreCase) ? "Dark" : "Light";
        App.SetTheme(next);
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

    private void Window_StateChanged(object sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            Hide();
            ShowInTaskbar = false;
        }
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_isClosingFromTray)
        {
            e.Cancel = true;
            Hide();
            ShowInTaskbar = false;
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
