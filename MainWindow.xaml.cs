using System.Windows;
using System.Windows.Controls;
using WinFirewallConsole.Firewall;

namespace WinFirewallConsole;

public partial class MainWindow : Window
{
    private readonly FirewallEngine _engine = new();
    private List<FirewallRuleModel> _allRules = new();

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Check enforce on startup from settings.ini
        var enforceStartup = App.Settings.GetValue("Policy", "EnforceOnStartup", "true");
        if (bool.TryParse(enforceStartup, out bool enforce) && enforce)
        {
            var (disabled, retained) = _engine.EnforceLockdownPolicy();
            StatusLabel.Text = $"Startup Enforce: Disabled {disabled} unapproved rules, retained {retained}.";
        }

        ReloadRules();
    }

    private void ReloadRules()
    {
        StatusLabel.Text = "Querying Windows Firewall COM interface...";
        _allRules = _engine.GetAllRules();
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

    private void Refresh_Click(object sender, RoutedEventArgs e) => ReloadRules();

    private void ThemeToggle_Click(object sender, RoutedEventArgs e)
    {
        var currentTheme = App.Settings.GetValue("Appearance", "Theme", "Dark");
        var targetTheme = currentTheme.Equals("Dark", StringComparison.OrdinalIgnoreCase) ? "Light" : "Dark";
        App.SetTheme(targetTheme);
    }

    private void EnforceLockdown_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "This will immediately DISABLE all enabled rules that are NOT approved or part of 'Core Networking'. Proceed?",
            "Confirm Firewall Lockdown",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            var (disabled, retained) = _engine.EnforceLockdownPolicy();
            ReloadRules();
            MessageBox.Show($"Lockdown applied successfully!\n\nDisabled unapproved rules: {disabled}\nRetained valid rules: {retained}",
                "Lockdown Finished", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void Approve_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is FirewallRuleModel selected)
        {
            _engine.ApproveRule(selected.Name);
            ReloadRules();
        }
    }

    private void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is FirewallRuleModel selected)
        {
            _engine.RevokeRule(selected.Name);
            ReloadRules();
        }
    }
}
