using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using FirewallConsole.Firewall;
using WinForms = System.Windows.Forms;

namespace FirewallConsole;

public partial class MainWindow : Window
{
    private readonly FirewallEngine _engine = new();
    private List<FirewallRuleModel> _allRules = new();
    private bool _isWhitelistMode = true;
    private WinForms.NotifyIcon? _notifyIcon;
    private readonly DispatcherTimer _watchdogTimer = new();
    private bool _isClosingFromTray = false;

    public MainWindow()
    {
        InitializeComponent();
        InitializeTray();
        Loaded += MainWindow_Loaded;

        // Periodic watchdog: In Whitelist mode, silently suppresses unauthorized allow rules every 10 seconds
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

    private void InitializeTray()
    {
        _notifyIcon = new WinForms.NotifyIcon
        {
            Text = "Firewall Console",
            Visible = true
        };

        var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.png");
        if (File.Exists(iconPath))
        {
            try
            {
                using var bmp = new Bitmap(iconPath);
                _notifyIcon.Icon = Icon.FromHandle(bmp.GetHicon());
            }
            catch
            {
                _notifyIcon.Icon = SystemIcons.Shield;
            }
        }
        else
        {
            _notifyIcon.Icon = SystemIcons.Shield;
        }

        var menu = new WinForms.ContextMenuStrip();
        var openItem = new WinForms.ToolStripMenuItem("Open Console", null, (s, e) => RestoreWindow());
        var toggleItem = new WinForms.ToolStripMenuItem("Toggle Mode", null, (s, e) => Dispatcher.Invoke(ToggleMode));
        var exitItem = new WinForms.ToolStripMenuItem("Exit", null, (s, e) => Dispatcher.Invoke(ExitApp));

        menu.Items.Add(openItem);
        menu.Items.Add(toggleItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(exitItem);

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

            StatusLabel.Text = "Applying configured firewall policy...";
            var (affected, retained) = await Task.Run(() => _engine.SetOperatingMode(_isWhitelistMode));

            await ReloadRulesAsync();
            _watchdogTimer.Start();

            StatusLabel.Text = _isWhitelistMode
                ? $"Whitelist Active: Suppressed {affected} unapproved allow rules. Retained {retained} rules."
                : $"Blacklist Active: Restored {affected} rules. Operating permissively.";
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
        StatsLabel.Text = $"Total Inbound: {_allRules.Count(r => r.Direction == "Inbound")} | Total Outbound: {_allRules.Count(r => r.Direction == "Outbound")}";
    }

    private void ApplyFilter()
    {
        var filter = SearchBox.Text.Trim();
        var currentTab = (RulesTabControl.SelectedItem as TabItem)?.Header?.ToString() ?? "Inbound Rules";
        bool isInbound = currentTab.Contains("Inbound");

        var targetList = _allRules.Where(r => isInbound ? r.Direction == "Inbound" : r.Direction == "Outbound");

        if (!string.IsNullOrWhiteSpace(filter))
        {
            targetList = targetList.Where(r =>
                r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.ApplicationName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.LocalPorts.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        var result = targetList.ToList();
        if (isInbound) InboundGrid.ItemsSource = result;
        else OutboundGrid.ItemsSource = result;
    }

    private DataGrid GetActiveGrid() =>
        RulesTabControl.SelectedIndex == 0 ? InboundGrid : OutboundGrid;

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
            ? "Switching to Whitelist: Suppressing unapproved allow rules..."
            : "Switching to Blacklist: Restoring allow rules...";

        var (affected, retained) = await Task.Run(() => _engine.SetOperatingMode(_isWhitelistMode));
        await ReloadRulesAsync();

        if (_isWhitelistMode)
        {
            MessageBox.Show($"Whitelist Mode Active!\n\nSuppressed {affected} unapproved allow rules.\nRetained {retained} rules.",
                            "Whitelist Engaged", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show($"Blacklist Mode Active!\n\nRestored {affected} rules back to active state.",
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

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var current = App.Config.GetValue("Settings", "Theme", "Light");
        var next = current.Equals("Light", StringComparison.OrdinalIgnoreCase) ? "Dark" : "Light";
        App.SetTheme(next);
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files != null && files.Length > 0 && files[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
                return;
            }
        }
        e.Effects = DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
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
            // Minimize to system tray on window close
            e.Cancel = true;
            Hide();
            ShowInTaskbar = false;
        }
        else
        {
            _watchdogTimer.Stop();
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
