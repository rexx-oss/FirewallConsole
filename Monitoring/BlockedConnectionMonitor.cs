using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using FirewallConsole.Models;

namespace FirewallConsole.Monitoring;

public class BlockedConnectionMonitor : IDisposable
{
    private EventLogWatcher? _watcher;
    public event Action<BlockedConnectionModel>? BlockedConnectionReceived;
    public bool IsRunning { get; private set; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    public void Start()
    {
        if (IsRunning) return;

        // Ensure Security Audit for Filtering Platform Connection failures is active
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/set /subcategory:\"Filtering Platform Connection\" /failure:enable",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            proc?.WaitForExit(1000);
        }
        catch { }

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5157)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += Watcher_EventRecordWritten;
            _watcher.Enabled = true;
            IsRunning = true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to start EventLogWatcher: {ex.Message}");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        try
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= Watcher_EventRecordWritten;
                _watcher.Dispose();
                _watcher = null;
            }
        }
        catch { }

        IsRunning = false;
    }

    private void Watcher_EventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;

        try
        {
            var props = e.EventRecord.Properties;
            if (props == null || props.Count < 8) return;

            string rawApp = props[1]?.Value?.ToString() ?? "Unknown";
            string resolvedApp = ResolveDevicePath(rawApp);

            string dirRaw = props[2]?.Value?.ToString() ?? "";
            string direction = dirRaw.Contains("14592") ? "Inbound" : "Outbound";

            string srcIp = props[3]?.Value?.ToString() ?? "*";
            string srcPort = props[4]?.Value?.ToString() ?? "*";
            string dstIp = props[5]?.Value?.ToString() ?? "*";
            string dstPort = props[6]?.Value?.ToString() ?? "*";

            int protoNum = Convert.ToInt32(props[7]?.Value ?? 0);
            string protoStr = protoNum switch
            {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMPv4",
                _ => protoNum.ToString()
            };

            var item = new BlockedConnectionModel
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                ApplicationName = resolvedApp,
                Direction = direction,
                Protocol = protoStr,
                Source = $"{srcIp}:{srcPort}",
                Destination = $"{dstIp}:{dstPort}"
            };

            BlockedConnectionReceived?.Invoke(item);
        }
        catch { }
    }

    private static string ResolveDevicePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return "Unknown";
        if (!rawPath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
            return rawPath;

        foreach (var drive in Environment.GetLogicalDrives())
        {
            string driveLetter = drive.TrimEnd('\\');
            var sb = new StringBuilder(260);
            if (QueryDosDevice(driveLetter, sb, sb.Capacity) > 0)
            {
                string devPath = sb.ToString();
                if (rawPath.StartsWith(devPath, StringComparison.OrdinalIgnoreCase))
                {
                    return driveLetter + rawPath.Substring(devPath.Length);
                }
            }
        }
        return Path.GetFileName(rawPath);
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
