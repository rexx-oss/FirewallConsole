using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FirewallConsole.Storage;

public class IniConfig
{
    private readonly Dictionary<string, Dictionary<string, string>> _data = 
        new(StringComparer.OrdinalIgnoreCase);

    public void Load(string filePath)
    {
        _data.Clear();
        if (!File.Exists(filePath)) return;

        string currentSection = "General";
        _data[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in File.ReadAllLines(filePath, Encoding.UTF8))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(';') || line.StartsWith('#'))
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1].Trim();
                if (!_data.ContainsKey(currentSection))
                    _data[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                var idx = line.IndexOf('=');
                if (idx > 0)
                {
                    var key = line[..idx].Trim();
                    var val = line[(idx + 1)..].Trim();
                    _data[currentSection][key] = val;
                }
            }
        }
    }

    public void Save(string filePath)
    {
        var sb = new StringBuilder();
        foreach (var section in _data)
        {
            sb.AppendLine($"[{section.Key}]");
            foreach (var kvp in section.Value)
            {
                sb.AppendLine($"{kvp.Key}={kvp.Value}");
            }
            sb.AppendLine();
        }
        File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    public string GetValue(string section, string key, string defaultValue = "")
    {
        if (_data.TryGetValue(section, out var s) && s.TryGetValue(key, out var val))
            return val;
        return defaultValue;
    }

    public void SetValue(string section, string key, string value)
    {
        if (!_data.ContainsKey(section))
            _data[section] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        _data[section][key] = value;
    }

    public IEnumerable<string> GetKeys(string section)
    {
        if (_data.TryGetValue(section, out var sec))
            return sec.Keys;
        return Enumerable.Empty<string>();
    }

    public void RemoveKey(string section, string key)
    {
        if (_data.TryGetValue(section, out var sec))
            sec.Remove(key);
    }
}
