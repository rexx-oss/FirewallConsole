using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
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
            throw new PlatformNotSupportedException("Windows Firewall COM interface (HNetCfg.FwPolicy2) is not registered on this system.");

        return Activator.CreateInstance(type)!;
    }

    public static bool IsCoreNetworkingGroup(string? grouping)
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
                bool isCore = IsCoreNetworkingGroup(grouping);
                bool isApproved = isCore || _approvedRulesIni.GetValue("ApprovedRules", name, "false") == "true";

                list.Add(new FirewallRuleModel
                {
                    Name = name,
                    Grouping = grouping,
                    ApplicationName = rule.ApplicationName ?? "",
                    Enabled = rule.Enabled,
                    Direction = rule.Direction == 1 ? "Inbound" : "Outbound",
                    Action = rule.Action == 1 ? "Allow" : "Block",
                    Protocol = rule.Protocol.ToString(),
                    LocalPorts = rule.LocalPorts ?? "*",
                    IsApproved = isApproved,
                    IsCoreNetworking = isCore
                });
            }
            catch
            {
                // Continue reading even if a single rule has non-standard parameters
            }
        }
        return list;
    }

    public void ApproveRule(string ruleName)
    {
        _approvedRulesIni.SetValue("ApprovedRules", ruleName, "true");
        _approvedRulesIni.Save(_rulesFilePath);
        SetRuleEnabled(ruleName, true);
    }

    public void RevokeRule(string ruleName)
    {
        _approvedRulesIni.RemoveKey("ApprovedRules", ruleName);
        _approvedRulesIni.Save(_rulesFilePath);
        SetRuleEnabled(ruleName, false);
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

    public (int disabledCount, int retainedCount) EnforceLockdownPolicy()
    {
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;

        int disabled = 0;
        int retained = 0;

        foreach (dynamic rule in rules)
        {
            try
            {
                string name = rule.Name ?? "";
                string grouping = rule.Grouping ?? "";

                bool isCore = IsCoreNetworkingGroup(grouping);
                bool isApproved = _approvedRulesIni.GetValue("ApprovedRules", name, "false") == "true";

                if (isCore || isApproved)
                {
                    retained++;
                }
                else
                {
                    if (rule.Enabled)
                    {
                        rule.Enabled = false;
                        disabled++;
                    }
                }
            }
            catch
            {
                // Skip rules locked by active Group Policy or system domain controllers
            }
        }

        return (disabled, retained);
    }
}
