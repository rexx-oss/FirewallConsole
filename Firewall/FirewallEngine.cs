using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
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

    private static string ConvertProtocol(int protoNum) => protoNum switch
    {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMPv4",
        58 => "ICMPv6",
        _ => "Any"
    };

    private static bool RuleMatches(dynamic rule, FirewallRuleModel target)
    {
        string name = (string)(rule.Name ?? "");
        string dir = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";
        string app = (string)(rule.ApplicationName ?? "");
        string proto = ConvertProtocol((int)rule.Protocol);
        string lp = (string)(rule.LocalPorts ?? "*");
        string rp = (string)(rule.RemotePorts ?? "*");

        string ruleId = FirewallRuleModel.ComputeRuleId(name, dir, app, proto, lp, rp);
        return string.Equals(ruleId, target.Id, StringComparison.OrdinalIgnoreCase);
    }

    public int SyncStoredRulesFromConfig()
    {
        int restoredCount = 0;
        var existingRules = GetAllRules();
        var existingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in existingRules)
        {
            existingIds.Add(r.Id);
        }

        foreach (var line in File.Exists(_iniPath) ? File.ReadAllLines(_iniPath) : Array.Empty<string>())
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("[Rule_", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith(']'))
            {
                string sec = trimmed[1..^1];
                string name = _config.GetValue(sec, "Name");
                string dir = _config.GetValue(sec, "Direction", "Outbound");
                string app = _config.GetValue(sec, "ApplicationName", "");
                string proto = _config.GetValue(sec, "Protocol", "Any");
                string lp = _config.GetValue(sec, "LocalPorts", "*");
                string rp = _config.GetValue(sec, "RemotePorts", "*");

                string ruleId = FirewallRuleModel.ComputeRuleId(name, dir, app, proto, lp, rp);

                if (!string.IsNullOrWhiteSpace(name) && !existingIds.Contains(ruleId))
                {
                    var model = new FirewallRuleModel
                    {
                        Id = ruleId,
                        Name = name,
                        Direction = dir,
                        Action = _config.GetValue(sec, "Action", "Allow"),
                        Enabled = bool.TryParse(_config.GetValue(sec, "Enabled", "True"), out bool en) && en,
                        Protocol = proto,
                        LocalPorts = lp,
                        RemotePorts = rp,
                        ApplicationName = app,
                        Profiles = _config.GetValue(sec, "Profiles", "All"),
                        IsApproved = bool.TryParse(_config.GetValue(sec, "IsApproved", "True"), out bool ap) && ap
                    };

                    try
                    {
                        AddRule(model);
                        restoredCount++;
                    }
                    catch { }
                }
            }
        }
        return restoredCount;
    }

    public List<FirewallRuleModel> GetAllRules()
    {
        var list = new List<FirewallRuleModel>();
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;

        try
        {
            foreach (dynamic rule in rules)
            {
                try
                {
                    string name = rule.Name ?? "";
                    string grouping = rule.Grouping ?? "";
                    string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";
                    string app = rule.ApplicationName ?? "";
                    string protoStr = ConvertProtocol((int)rule.Protocol);
                    string lp = rule.LocalPorts ?? "*";
                    string rp = rule.RemotePorts ?? "*";

                    string ruleId = FirewallRuleModel.ComputeRuleId(name, direction, app, protoStr, lp, rp);

                    bool isCore = IsCoreNetworking(grouping);
                    bool isApproved = isCore || _config.GetValue("ApprovedRules", ruleId, "false") == "true";

                    list.Add(new FirewallRuleModel
                    {
                        Id = ruleId,
                        Name = name,
                        Description = rule.Description ?? "",
                        Grouping = grouping,
                        ApplicationName = app,
                        Enabled = rule.Enabled,
                        Direction = direction,
                        Action = ((int)rule.Action) == 1 ? "Allow" : "Block",
                        Protocol = protoStr,
                        LocalPorts = lp,
                        RemotePorts = rp,
                        LocalAddresses = rule.LocalAddresses ?? "*",
                        RemoteAddresses = rule.RemoteAddresses ?? "*",
                        Profiles = ((int)rule.Profiles) == 0x7FFFFFFF ? "All" : rule.Profiles.ToString(),
                        IsApproved = isApproved
                    });
                }
                catch { }
                finally
                {
                    if (rule != null && Marshal.IsComObject(rule))
                    {
                        Marshal.ReleaseComObject(rule);
                    }
                }
            }
        }
        finally
        {
            if (rules != null && Marshal.IsComObject(rules)) Marshal.ReleaseComObject(rules);
            if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
        }
        return list;
    }

    public (int affectedCount, int retainedCount) SetOperatingMode(bool whitelistMode)
    {
        dynamic policy = GetPolicy();
        int affected = 0;
        int retained = 0;

        int defaultOutbound = whitelistMode ? 0 : 1;
        try
        {
            policy.DefaultOutboundAction[1] = defaultOutbound;
            policy.DefaultOutboundAction[2] = defaultOutbound;
            policy.DefaultOutboundAction[4] = defaultOutbound;
        }
        catch { }

        dynamic rules = policy.Rules;
        var autoDisabledMap = new HashSet<string>(_config.GetKeys("AutoDisabled"), StringComparer.OrdinalIgnoreCase);

        try
        {
            if (whitelistMode)
            {
                foreach (dynamic rule in rules)
                {
                    try
                    {
                        if ((int)rule.Action != 1) continue;

                        string name = rule.Name ?? "";
                        string grouping = rule.Grouping ?? "";
                        string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";
                        string app = rule.ApplicationName ?? "";
                        string protoStr = ConvertProtocol((int)rule.Protocol);
                        string lp = rule.LocalPorts ?? "*";
                        string rp = rule.RemotePorts ?? "*";

                        string ruleId = FirewallRuleModel.ComputeRuleId(name, direction, app, protoStr, lp, rp);

                        bool isCore = IsCoreNetworking(grouping);
                        bool isApproved = isCore || _config.GetValue("ApprovedRules", ruleId, "false") == "true";

                        if (isApproved)
                        {
                            retained++;
                        }
                        else if ((bool)rule.Enabled)
                        {
                            rule.Enabled = false;
                            _config.SetValue("AutoDisabled", ruleId, "true");
                            affected++;
                        }
                    }
                    catch { }
                    finally
                    {
                        if (rule != null && Marshal.IsComObject(rule)) Marshal.ReleaseComObject(rule);
                    }
                }
            }
            else
            {
                foreach (dynamic rule in rules)
                {
                    try
                    {
                        string name = rule.Name ?? "";
                        string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";
                        string app = rule.ApplicationName ?? "";
                        string protoStr = ConvertProtocol((int)rule.Protocol);
                        string lp = rule.LocalPorts ?? "*";
                        string rp = rule.RemotePorts ?? "*";

                        string ruleId = FirewallRuleModel.ComputeRuleId(name, direction, app, protoStr, lp, rp);

                        if (autoDisabledMap.Contains(ruleId))
                        {
                            rule.Enabled = true;
                            affected++;
                        }
                    }
                    catch { }
                    finally
                    {
                        if (rule != null && Marshal.IsComObject(rule)) Marshal.ReleaseComObject(rule);
                    }
                }
                _config.RemoveSection("AutoDisabled");
            }
        }
        finally
        {
            if (rules != null && Marshal.IsComObject(rules)) Marshal.ReleaseComObject(rules);
            if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
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

        model.Id = FirewallRuleModel.ComputeRuleId(model.Name, model.Direction, model.ApplicationName, model.Protocol, model.LocalPorts, model.RemotePorts);
        SaveRuleToConfig(model);

        if (newRule != null && Marshal.IsComObject(newRule)) Marshal.ReleaseComObject(newRule);
        if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
    }

    public void UpdateRule(FirewallRuleModel oldModel, FirewallRuleModel newModel)
    {
        DeleteRule(oldModel);
        AddRule(newModel);
    }

    private void SaveRuleToConfig(FirewallRuleModel model)
    {
        if (string.IsNullOrWhiteSpace(model.Id))
        {
            model.Id = FirewallRuleModel.ComputeRuleId(model.Name, model.Direction, model.ApplicationName, model.Protocol, model.LocalPorts, model.RemotePorts);
        }

        string sec = $"Rule_{model.Id}";
        _config.SetValue(sec, "Id", model.Id);
        _config.SetValue(sec, "Name", model.Name);
        _config.SetValue(sec, "Direction", model.Direction);
        _config.SetValue(sec, "Action", model.Action);
        _config.SetValue(sec, "Enabled", model.Enabled.ToString());
        _config.SetValue(sec, "Protocol", model.Protocol);
        _config.SetValue(sec, "LocalPorts", model.LocalPorts);
        _config.SetValue(sec, "RemotePorts", model.RemotePorts);
        _config.SetValue(sec, "ApplicationName", model.ApplicationName);
        _config.SetValue(sec, "Profiles", model.Profiles);
        _config.SetValue(sec, "IsApproved", model.IsApproved.ToString());

        if (model.IsApproved)
        {
            _config.SetValue("ApprovedRules", model.Id, "true");
        }
        else
        {
            _config.RemoveKey("ApprovedRules", model.Id);
        }

        _config.Save(_iniPath);
    }

    public void SetRuleEnabled(FirewallRuleModel target, bool enabled)
    {
        dynamic policy = GetPolicy();
        try
        {
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    if (RuleMatches(rule, target))
                    {
                        rule.Enabled = enabled;
                    }
                }
                finally
                {
                    if (rule != null && Marshal.IsComObject(rule)) Marshal.ReleaseComObject(rule);
                }
            }
        }
        finally
        {
            if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
        }

        target.Enabled = enabled;
        _config.SetValue($"Rule_{target.Id}", "Enabled", enabled.ToString());
        _config.Save(_iniPath);
    }

    public void ToggleRuleAction(FirewallRuleModel target)
    {
        dynamic policy = GetPolicy();
        string newAction = "Allow";
        try
        {
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    if (RuleMatches(rule, target))
                    {
                        int currentAction = (int)rule.Action;
                        rule.Action = currentAction == 1 ? 0 : 1;
                        newAction = currentAction == 1 ? "Block" : "Allow";
                    }
                }
                finally
                {
                    if (rule != null && Marshal.IsComObject(rule)) Marshal.ReleaseComObject(rule);
                }
            }
        }
        finally
        {
            if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
        }

        target.Action = newAction;
        _config.SetValue($"Rule_{target.Id}", "Action", newAction);
        _config.Save(_iniPath);
    }

    public void ApproveRule(FirewallRuleModel target)
    {
        target.IsApproved = true;
        _config.SetValue("ApprovedRules", target.Id, "true");
        _config.RemoveKey("AutoDisabled", target.Id);
        SaveRuleToConfig(target);
    }

    public void RevokeRule(FirewallRuleModel target)
    {
        target.IsApproved = false;
        _config.RemoveKey("ApprovedRules", target.Id);
        SaveRuleToConfig(target);

        if (target.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
        {
            SetRuleEnabled(target, false);
        }
    }

    public void DeleteRule(FirewallRuleModel target)
    {
        dynamic policy = GetPolicy();
        try
        {
            policy.Rules.Remove(target.Name);
        }
        catch { }
        finally
        {
            if (policy != null && Marshal.IsComObject(policy)) Marshal.ReleaseComObject(policy);
        }

        _config.RemoveSection($"Rule_{target.Id}");
        _config.RemoveKey("ApprovedRules", target.Id);
        _config.RemoveKey("AutoDisabled", target.Id);
        _config.Save(_iniPath);
    }
}
