using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using FirewallConsole.Firewall;
using Microsoft.Win32;

namespace FirewallConsole;

public partial class RuleDialog : Window
{
    public FirewallRuleModel? CreatedRule { get; private set; }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    public RuleDialog(string? prefilledPath = null, string? direction = null, string? protocol = null)
    {
        InitializeComponent();
        SourceInitialized += (s, e) => ApplyTitleBarTheme();

        if (!string.IsNullOrWhiteSpace(prefilledPath))
        {
            TxtAppPath.Text = prefilledPath;
            TxtName.Text = Path.GetFileNameWithoutExtension(prefilledPath);
        }
        if (!string.IsNullOrWhiteSpace(direction))
        {
            SelectComboValue(CmbDirection, direction);
        }
        if (!string.IsNullOrWhiteSpace(protocol))
        {
            SelectComboValue(CmbProtocol, protocol);
        }
    }

    public RuleDialog(FirewallRuleModel existingRule)
    {
        InitializeComponent();
        SourceInitialized += (s, e) => ApplyTitleBarTheme();

        DialogTitle.Text = $"Edit Rule: {existingRule.Name}";
        BtnSave.Content = "Save Changes";

        TxtName.Text = existingRule.Name;
        TxtAppPath.Text = existingRule.ApplicationName;
        TxtLocalPort.Text = existingRule.LocalPorts;
        TxtRemotePort.Text = existingRule.RemotePorts;
        ChkEnabled.IsChecked = existingRule.Enabled;
        ChkApproved.IsChecked = existingRule.IsApproved;

        SelectComboValue(CmbDirection, existingRule.Direction);
        SelectComboValue(CmbAction, existingRule.Action);
        SelectComboValue(CmbProtocol, existingRule.Protocol);
        SelectComboValue(CmbProfiles, existingRule.Profiles);
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

    private static void SelectComboValue(ComboBox cmb, string val)
    {
        for (int i = 0; i < cmb.Items.Count; i++)
        {
            if (cmb.Items[i] is ComboBoxItem item &&
                item.Content.ToString()!.Equals(val, StringComparison.OrdinalIgnoreCase))
            {
                cmb.SelectedIndex = i;
                return;
            }
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
