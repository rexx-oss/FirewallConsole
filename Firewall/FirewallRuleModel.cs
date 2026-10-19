using System;
using System.Security.Cryptography;
using System.Text;

namespace FirewallConsole.Firewall;

public class FirewallRuleModel
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Grouping { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string Direction { get; set; } = "Inbound";
    public string Action { get; set; } = "Allow";
    public string Protocol { get; set; } = "Any";
    public string LocalPorts { get; set; } = "*";
    public string RemotePorts { get; set; } = "*";
    public string LocalAddresses { get; set; } = "*";
    public string RemoteAddresses { get; set; } = "*";
    public string Profiles { get; set; } = "All";
    public bool IsApproved { get; set; }

    public static string ComputeRuleId(string name, string direction, string appPath, string protocol, string localPorts, string remotePorts)
    {
        string raw = $"{name?.Trim()}|{direction?.Trim()}|{appPath?.Trim()}|{protocol?.Trim()}|{localPorts?.Trim()}|{remotePorts?.Trim()}".ToLowerInvariant();
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes)[..16];
    }
}
