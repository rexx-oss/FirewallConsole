namespace FirewallConsole.Models;

public class BlockedConnectionModel
{
    public string Timestamp { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public string Direction { get; set; } = "Outbound";
    public string Protocol { get; set; } = "TCP";
    public string Destination { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
}
