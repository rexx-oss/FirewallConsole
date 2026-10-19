using System;
using System.Collections.Generic;
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

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var enforceStartup = App.Settings.GetValue("Policy", "EnforceOnStartup", "true");
            if (bool.TryParse(enforceStartup, out bool enforce) && enforce)
            {
                StatusLabel.Text = "Applying startup policy...";
                var (disabled, retained) = await Task.Run(() => _engine.EnforceLockdownPolicy());
                StatusLabel.Text = $"Startup Enforce: Disabled {disabled} rules, retained {retained}.";
            }

            await ReloadRulesAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Startup initialization error: {ex.Message}\n\nMake sure to run as Administrator.", 
                            "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            StatusLabel.Text = "Failed to communicate with Windows Firewall.";
        }
    }

    private async Task ReloadRulesAsync()
    {
        StatusLabel.Text = "Querying Windows Firewall COM interface...";
        _allRules = await Task.Run(() => _engine.GetAllRules());
        ApplyFilter();
        StatsLabel.Text = $"Total Rules: {_allRules.Count}";
        StatusLabel.Text = "Rules loaded and synchronized.";
    }

    private void ApplyFilter()
    {
        var filter = SearchBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(filter))
        {
            RulesGrid.ItemsSource = _allRules;
        }
        else
        {
            RulesGrid.ItemsSource = _allRules.Where(r => 
                r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.Grouping.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                r.ApplicationName.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await ReloadRulesAsync();

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var currentTheme = App.Settings.GetValue("Appearance", "Theme", "Dark");
        var targetTheme = currentTheme.Equals("Dark", StringComparison.OrdinalIgnoreCase) ? "Light" : "Dark";
        App.SetTheme(targetTheme);
    }

    private async void EnforceLockdown_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "This will immediately DISABLE all rules that are NOT approved or part of 'Core Networking'. Proceed?",
            "Confirm Firewall Lockdown",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            StatusLabel.Text = "Enforcing lockdown...";
            var (disabled, retained) = await Task.Run(() => _engine.EnforceLockdownPolicy());
            await ReloadRulesAsync();
            MessageBox.Show($"Lockdown finished!\n\nDisabled rules: {disabled}\nRetained valid rules: {retained}",
                "Lockdown Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async void Approve_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is FirewallRuleModel selected)
        {
            await Task.Run(() => _engine.ApproveRule(selected.Name));
            await ReloadRulesAsync();
        }
    }

    private async void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is FirewallRuleModel selected)
        {
            await Task.Run(() => _engine.RevokeRule(selected.Name));
            await ReloadRulesAsync();
        }
    }
}
