namespace FirewallConsole.Firewall;

public class FirewallRuleModel
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Grouping { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string Direction { get; set; } = "Inbound"; // "Inbound" or "Outbound"
    public string Action { get; set; } = "Allow";       // "Allow" or "Block"
    public string Protocol { get; set; } = "Any";      // "TCP", "UDP", "ICMPv4", "Any"
    public string LocalPorts { get; set; } = "*";
    public string RemotePorts { get; set; } = "*";
    public string LocalAddresses { get; set; } = "*";
    public string RemoteAddresses { get; set; } = "*";
    public string Profiles { get; set; } = "All";      // "All", "Domain", "Private", "Public"
    public bool IsApproved { get; set; }
}
