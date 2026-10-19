namespace FirewallConsole.Firewall;

public class FirewallRuleModel
{
    public string Name { get; set; } = string.Empty;
    public string Grouping { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string Direction { get; set; } = "Inbound";
    public string Action { get; set; } = "Allow";
    public string Protocol { get; set; } = "Any";
    public string LocalPorts { get; set; } = "Any";
    public bool IsApproved { get; set; }
    public bool IsCoreNetworking { get; set; }
}
