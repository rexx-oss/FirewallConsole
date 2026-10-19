using System.IO;
using System.Windows;
using System.Windows.Controls;
using FirewallConsole.Firewall;
using Microsoft.Win32;

namespace FirewallConsole;

public partial class RuleDialog : Window
{
    public FirewallRuleModel? CreatedRule { get; private set; }

    public RuleDialog(string? prefilledPath = null)
    {
        InitializeComponent();

        if (!string.IsNullOrWhiteSpace(prefilledPath))
        {
            TxtAppPath.Text = prefilledPath;
            TxtName.Text = Path.GetFileNameWithoutExtension(prefilledPath);
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var ofd = new OpenFileDialog
        {
            Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select Application Executable"
        };
        if (ofd.ShowDialog() == true)
        {
            TxtAppPath.Text = ofd.FileName;
            if (string.IsNullOrWhiteSpace(TxtName.Text))
            {
                TxtName.Text = Path.GetFileNameWithoutExtension(ofd.FileName);
            }
        }
    }

    private void Create_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TxtName.Text))
        {
            MessageBox.Show("Please enter a rule name.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        CreatedRule = new FirewallRuleModel
        {
            Name = TxtName.Text.Trim(),
            ApplicationName = TxtAppPath.Text.Trim(),
            Direction = ((ComboBoxItem)CmbDirection.SelectedItem).Content.ToString()!,
            Action = ((ComboBoxItem)CmbAction.SelectedItem).Content.ToString()!,
            Protocol = ((ComboBoxItem)CmbProtocol.SelectedItem).Content.ToString()!,
            Profiles = ((ComboBoxItem)CmbProfiles.SelectedItem).Content.ToString()!,
            LocalPorts = string.IsNullOrWhiteSpace(TxtLocalPort.Text) ? "*" : TxtLocalPort.Text.Trim(),
            RemotePorts = string.IsNullOrWhiteSpace(TxtRemotePort.Text) ? "*" : TxtRemotePort.Text.Trim(),
            Enabled = ChkEnabled.IsChecked ?? true,
            IsApproved = ChkApproved.IsChecked ?? true
        };

        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
