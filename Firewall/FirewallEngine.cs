using System;
using System.Collections.Generic;
using System.IO;
using FirewallConsole.Storage;

namespace FirewallConsole.Firewall;

public class FirewallEngine
{
    private readonly IniConfig _config = new();
    private readonly string _iniPath;

    public FirewallEngine()
    {
        _iniPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "firecon.ini");
        _config.Load(_iniPath);
    }

    public IniConfig Config => _config;
    public string ConfigPath => _iniPath;

    private static dynamic GetPolicy()
    {
        Type? type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                     ?? Type.GetTypeFromCLSID(new Guid("{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}"));

        if (type == null)
            throw new PlatformNotSupportedException("Windows Firewall COM interface is not registered on this system.");

        return Activator.CreateInstance(type)!;
    }

    public static bool IsCoreNetworking(string? grouping)
    {
        if (string.IsNullOrWhiteSpace(grouping)) return false;
        return grouping.Contains("-25000", StringComparison.OrdinalIgnoreCase) ||
               grouping.Contains("Core Networking", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetSectionForDirection(string direction) =>
        direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase) ? "InboundApproved" : "OutboundApproved";

    private static bool RuleMatches(dynamic rule, FirewallRuleModel target)
    {
        if (!string.Equals((string)(rule.Name ?? ""), target.Name, StringComparison.OrdinalIgnoreCase))
            return false;

        int dir = (int)rule.Direction;
        int targetDir = target.Direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase) ? 1 : 2;
        if (dir != targetDir)
            return false;

        string app = (string)(rule.ApplicationName ?? "");
        if (!string.Equals(app, target.ApplicationName, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    public List<FirewallRuleModel> GetAllRules()
    {
        var list = new List<FirewallRuleModel>();
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;

        foreach (dynamic rule in rules)
        {
            try
            {
                string name = rule.Name ?? "";
                string grouping = rule.Grouping ?? "";
                string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";
                bool isCore = IsCoreNetworking(grouping);

                string section = GetSectionForDirection(direction);
                bool isApproved = isCore || _config.GetValue(section, name, "false") == "true";

                int protoNum = (int)rule.Protocol;
                string protoStr = protoNum switch
                {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMPv4",
                    58 => "ICMPv6",
                    _ => "Any"
                };

                list.Add(new FirewallRuleModel
                {
                    Name = name,
                    Description = rule.Description ?? "",
                    Grouping = grouping,
                    ApplicationName = rule.ApplicationName ?? "",
                    Enabled = rule.Enabled,
                    Direction = direction,
                    Action = ((int)rule.Action) == 1 ? "Allow" : "Block",
                    Protocol = protoStr,
                    LocalPorts = rule.LocalPorts ?? "*",
                    RemotePorts = rule.RemotePorts ?? "*",
                    LocalAddresses = rule.LocalAddresses ?? "*",
                    RemoteAddresses = rule.RemoteAddresses ?? "*",
                    Profiles = ((int)rule.Profiles) == 0x7FFFFFFF ? "All" : rule.Profiles.ToString(),
                    IsApproved = isApproved
                });
            }
            catch
            {
                // Continue scanning even if an individual rule is inaccessible
            }
        }
        return list;
    }

    /// <summary>
    /// Strict Whitelist Mode: Disables unapproved allow rules and tracks them in [AutoDisabled].
    /// Permissive Blacklist Mode: Restores previously auto-disabled rules.
    /// </summary>
    public (int affectedCount, int retainedCount) SetOperatingMode(bool whitelistMode)
    {
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;
        int affected = 0;
        int retained = 0;

        if (whitelistMode)
        {
            foreach (dynamic rule in rules)
            {
                try
                {
                    int action = (int)rule.Action; // 1 = Allow, 0 = Block
                    if (action != 1) continue;      // Block rules remain untouched

                    string name = rule.Name ?? "";
                    string grouping = rule.Grouping ?? "";
                    string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";

                    bool isCore = IsCoreNetworking(grouping);
                    string section = GetSectionForDirection(direction);
                    bool isApproved = isCore || _config.GetValue(section, name, "false") == "true";

                    if (isApproved)
                    {
                        retained++;
                    }
                    else if ((bool)rule.Enabled)
                    {
                        rule.Enabled = false;
                        _config.SetValue("AutoDisabled", $"{direction}|{name}", "true");
                        affected++;
                    }
                }
                catch { }
            }
        }
        else
        {
            // Restore rules that were suppressed by Whitelist mode
            var autoDisabledKeys = new List<string>(_config.GetKeys("AutoDisabled"));
            foreach (var key in autoDisabledKeys)
            {
                var parts = key.Split('|');
                if (parts.Length != 2) continue;
                string dirStr = parts[0];
                string ruleName = parts[1];
                int targetDir = dirStr.Equals("Inbound", StringComparison.OrdinalIgnoreCase) ? 1 : 2;

                foreach (dynamic rule in rules)
                {
                    try
                    {
                        if (string.Equals((string)(rule.Name ?? ""), ruleName, StringComparison.OrdinalIgnoreCase) &&
                            (int)rule.Direction == targetDir)
                        {
                            rule.Enabled = true;
                            affected++;
                        }
                    }
                    catch { }
                }
                _config.RemoveKey("AutoDisabled", key);
            }
        }

        _config.SetValue("Settings", "Mode", whitelistMode ? "Whitelist" : "Blacklist");
        _config.Save(_iniPath);
        return (affected, retained);
    }

    public void AddRule(FirewallRuleModel model)
    {
        Type? ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
        if (ruleType == null)
            throw new PlatformNotSupportedException("Cannot create HNetCfg.FWRule COM object.");

        dynamic newRule = Activator.CreateInstance(ruleType)!;
        newRule.Name = model.Name;
        newRule.Description = model.Description;
        if (!string.IsNullOrWhiteSpace(model.ApplicationName))
            newRule.ApplicationName = model.ApplicationName;

        newRule.Direction = model.Direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase) ? 1 : 2;
        newRule.Action = model.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        newRule.Enabled = model.Enabled;

        int protocol = model.Protocol.ToUpperInvariant() switch
        {
            "TCP" => 6,
            "UDP" => 17,
            "ICMPV4" => 1,
            _ => 256
        };
        newRule.Protocol = protocol;

        if (protocol is 6 or 17)
        {
            if (!string.IsNullOrWhiteSpace(model.LocalPorts) && model.LocalPorts != "*")
                newRule.LocalPorts = model.LocalPorts;
            if (!string.IsNullOrWhiteSpace(model.RemotePorts) && model.RemotePorts != "*")
                newRule.RemotePorts = model.RemotePorts;
        }

        newRule.Profiles = model.Profiles.ToUpperInvariant() switch
        {
            "DOMAIN" => 1,
            "PRIVATE" => 2,
            "PUBLIC" => 4,
            _ => 0x7FFFFFFF
        };

        dynamic policy = GetPolicy();
        policy.Rules.Add(newRule);

        if (model.IsApproved)
        {
            string section = GetSectionForDirection(model.Direction);
            _config.SetValue(section, model.Name, "true");
            _config.Save(_iniPath);
        }
    }

    public void SetRuleEnabled(FirewallRuleModel target, bool enabled)
    {
        dynamic policy = GetPolicy();
        foreach (dynamic rule in policy.Rules)
        {
            if (RuleMatches(rule, target))
            {
                rule.Enabled = enabled;
            }
        }
    }

    public void ToggleRuleAction(FirewallRuleModel target)
    {
        dynamic policy = GetPolicy();
        foreach (dynamic rule in policy.Rules)
        {
            if (RuleMatches(rule, target))
            {
                int currentAction = (int)rule.Action;
                rule.Action = currentAction == 1 ? 0 : 1;
            }
        }
    }

    public void ApproveRule(FirewallRuleModel target)
    {
        string section = GetSectionForDirection(target.Direction);
        _config.SetValue(section, target.Name, "true");
        _config.RemoveKey("AutoDisabled", $"{target.Direction}|{target.Name}");
        _config.Save(_iniPath);
    }

    public void RevokeRule(FirewallRuleModel target)
    {
        string section = GetSectionForDirection(target.Direction);
        _config.RemoveKey(section, target.Name);
        _config.Save(_iniPath);

        if (target.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
        {
            SetRuleEnabled(target, false);
        }
    }

    public void DeleteRule(FirewallRuleModel target)
    {
        try
        {
            dynamic policy = GetPolicy();
            policy.Rules.Remove(target.Name);
        }
        catch { }

        string section = GetSectionForDirection(target.Direction);
        _config.RemoveKey(section, target.Name);
        _config.RemoveKey("AutoDisabled", $"{target.Direction}|{target.Name}");
        _config.Save(_iniPath);
    }
}
