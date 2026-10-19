using System;
using System.Collections.Generic;
using System.IO;
using FirewallConsole.Storage;

namespace FirewallConsole.Firewall;

public class FirewallEngine
{
    private readonly IniConfig _approvedRulesIni = new();
    private readonly string _rulesFilePath;

    public FirewallEngine()
    {
        var appDir = AppDomain.CurrentDomain.BaseDirectory;
        _rulesFilePath = Path.Combine(appDir, "approved_rules.ini");
        _approvedRulesIni.Load(_rulesFilePath);
    }

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
                bool isCore = IsCoreNetworking(grouping);
                bool isApproved = isCore || _approvedRulesIni.GetValue("ApprovedRules", name, "false") == "true";

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
                    Direction = rule.Direction == 1 ? "Inbound" : "Outbound",
                    Action = rule.Action == 1 ? "Allow" : "Block",
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
                // Continue scanning even if a single malformed rule is encountered
            }
        }
        return list;
    }

    /// <summary>
    /// Enforces mode: In Whitelist mode, automatically disables ONLY 'Allow' rules that are unapproved.
    /// Block rules are never disabled. Core Networking Allow rules are retained.
    /// </summary>
    public (int disabledAllowRules, int retainedRules) EnforceMode(bool whitelistMode)
    {
        if (!whitelistMode) return (0, 0);

        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;
        int disabledCount = 0;
        int retainedCount = 0;

        foreach (dynamic rule in rules)
        {
            try
            {
                int action = (int)rule.Action; // 1 = Allow, 0 = Block
                if (action != 1)
                {
                    // Block rules remain untouched
                    continue;
                }

                string name = rule.Name ?? "";
                string grouping = rule.Grouping ?? "";
                bool isCore = IsCoreNetworking(grouping);
                bool isApproved = isCore || _approvedRulesIni.GetValue("ApprovedRules", name, "false") == "true";

                if (isApproved)
                {
                    retainedCount++;
                }
                else
                {
                    if ((bool)rule.Enabled)
                    {
                        rule.Enabled = false;
                        disabledCount++;
                    }
                }
            }
            catch
            {
                // Skip rules protected by Active Directory or system domain controllers
            }
        }

        return (disabledCount, retainedCount);
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
            _ => 256 // Any
        };
        newRule.Protocol = protocol;

        if (protocol is 6 or 17)
        {
            if (!string.IsNullOrWhiteSpace(model.LocalPorts) && model.LocalPorts != "*")
                newRule.LocalPorts = model.LocalPorts;
            if (!string.IsNullOrWhiteSpace(model.RemotePorts) && model.RemotePorts != "*")
                newRule.RemotePorts = model.RemotePorts;
        }

        if (!string.IsNullOrWhiteSpace(model.LocalAddresses) && model.LocalAddresses != "*")
            newRule.LocalAddresses = model.LocalAddresses;
        if (!string.IsNullOrWhiteSpace(model.RemoteAddresses) && model.RemoteAddresses != "*")
            newRule.RemoteAddresses = model.RemoteAddresses;

        newRule.Profiles = model.Profiles.ToUpperInvariant() switch
        {
            "DOMAIN" => 1,
            "PRIVATE" => 2,
            "PUBLIC" => 4,
            _ => 0x7FFFFFFF // All
        };

        dynamic policy = GetPolicy();
        policy.Rules.Add(newRule);

        if (model.IsApproved)
        {
            _approvedRulesIni.SetValue("ApprovedRules", model.Name, "true");
            _approvedRulesIni.Save(_rulesFilePath);
        }
    }

    public void DeleteRule(string ruleName)
    {
        dynamic policy = GetPolicy();
        policy.Rules.Remove(ruleName);
        _approvedRulesIni.RemoveKey("ApprovedRules", ruleName);
        _approvedRulesIni.Save(_rulesFilePath);
    }

    public void SetRuleEnabled(string ruleName, bool enabled)
    {
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;
        foreach (dynamic rule in rules)
        {
            if (string.Equals(rule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                rule.Enabled = enabled;
            }
        }
    }

    public void ToggleRuleAction(string ruleName)
    {
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;
        foreach (dynamic rule in rules)
        {
            if (string.Equals(rule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                int currentAction = (int)rule.Action;
                rule.Action = currentAction == 1 ? 0 : 1; // Swap Allow (1) <-> Block (0)
            }
        }
    }

    public void ApproveRule(string ruleName)
    {
        _approvedRulesIni.SetValue("ApprovedRules", ruleName, "true");
        _approvedRulesIni.Save(_rulesFilePath);
    }

    public void RevokeRule(string ruleName)
    {
        _approvedRulesIni.RemoveKey("ApprovedRules", ruleName);
        _approvedRulesIni.Save(_rulesFilePath);
        // If revoking an allow rule, disable it immediately
        dynamic policy = GetPolicy();
        foreach (dynamic rule in policy.Rules)
        {
            if (string.Equals(rule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                if ((int)rule.Action == 1) rule.Enabled = false;
            }
        }
    }
}
