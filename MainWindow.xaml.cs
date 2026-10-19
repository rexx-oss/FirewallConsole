using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FirewallConsole.Firewall;
using FirewallConsole.Storage;

namespace FirewallConsole;

public partial class MainWindow : Window
{
    private readonly FirewallEngine _engine = new();
    private List<FirewallRuleModel> _allRules = new();
    private bool _isWhitelistMode = true;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            string mode = App.Settings.GetValue("Policy", "Mode", "Whitelist");
            _isWhitelistMode = mode.Equals("Whitelist", StringComparison.OrdinalIgnoreCase);
            UpdateModeButtonLabel();

            StatusLabel.Text = "Synchronizing and suppressing unapproved allow rules...";
            var (disabled, retained) = await Task.Run(() => _engine.EnforceMode(_isWhitelistMode));

            await ReloadRulesAsync();
            StatusLabel.Text = _isWhitelistMode
                ? $"Whitelist Active: Disabled {disabled} unapproved allow rules. Retained {retained} rules."
                : "Blacklist Mode Active: Operating permissively.";
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

    private List<FirewallRuleModel> GetSelectedRules()
    {
        var grid = GetActiveGrid();
        return grid.SelectedItems.Cast<FirewallRuleModel>().ToList();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void RulesTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source is TabControl) ApplyFilter();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        StatusLabel.Text = "Refreshing firewall rules...";
        await ReloadRulesAsync();
        StatusLabel.Text = "Refreshed.";
    }

    private async void ModeToggle_Click(object sender, RoutedEventArgs e)
    {
        _isWhitelistMode = !_isWhitelistMode;
        App.Settings.SetValue("Policy", "Mode", _isWhitelistMode ? "Whitelist" : "Blacklist");
        App.Settings.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.ini"));
        UpdateModeButtonLabel();

        if (_isWhitelistMode)
        {
            StatusLabel.Text = "Enforcing Whitelist mode...";
            var (disabled, retained) = await Task.Run(() => _engine.EnforceMode(true));
            await ReloadRulesAsync();
            MessageBox.Show($"Whitelist Mode engaged!\n\nDisabled {disabled} unapproved allow rules.\nRetained {retained} rules.",
                            "Whitelist Active", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            StatusLabel.Text = "Blacklist Mode active. Unapproved allow rules are not auto-suppressed.";
        }
    }

    private void UpdateModeButtonLabel()
    {
        ModeToggleButton.Content = _isWhitelistMode ? "🛡 Mode: Whitelist (Strict)" : "🔓 Mode: Blacklist (Permissive)";
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
            StatusLabel.Text = $"Rule '{dialog.CreatedRule.Name}' added successfully.";
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
            foreach (var r in selected)
            {
                _engine.SetRuleEnabled(r, true);
            }
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
            foreach (var r in selected)
            {
                _engine.SetRuleEnabled(r, false);
            }
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
            foreach (var r in selected)
            {
                _engine.ToggleRuleAction(r);
            }
        });
        await ReloadRulesAsync();
        StatusLabel.Text = $"Toggled action for {selected.Count} rule(s).";
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRules();
        if (selected.Count == 0) return;

        var res = MessageBox.Show($"Permanently delete {selected.Count} selected rule(s)?", "Confirm Delete",
                                  MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (res == MessageBoxResult.Yes)
        {
            StatusLabel.Text = $"Deleting {selected.Count} rule(s)...";
            await Task.Run(() =>
            {
                foreach (var r in selected)
                {
                    _engine.DeleteRule(r);
                }
            });
            await ReloadRulesAsync();
            StatusLabel.Text = $"Deleted {selected.Count} rule(s).";
        }
    }

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var current = App.Settings.GetValue("Appearance", "Theme", "Light");
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
}
