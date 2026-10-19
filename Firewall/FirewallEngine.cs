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

    private string GetSectionForDirection(string direction) =>
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
                bool isApproved = isCore || _approvedRulesIni.GetValue(section, name, "false") == "true";

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
                if (action != 1) continue;      // Block rules remain untouched

                string name = rule.Name ?? "";
                string grouping = rule.Grouping ?? "";
                string direction = ((int)rule.Direction) == 1 ? "Inbound" : "Outbound";

                bool isCore = IsCoreNetworking(grouping);
                string section = GetSectionForDirection(direction);
                bool isApproved = isCore || _approvedRulesIni.GetValue(section, name, "false") == "true";

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
                // Skip rules protected by Active Directory or domain policies
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
            _approvedRulesIni.SetValue(section, model.Name, "true");
            _approvedRulesIni.Save(_rulesFilePath);
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
        _approvedRulesIni.SetValue(section, target.Name, "true");
        _approvedRulesIni.Save(_rulesFilePath);
    }

    public void RevokeRule(FirewallRuleModel target)
    {
        string section = GetSectionForDirection(target.Direction);
        _approvedRulesIni.RemoveKey(section, target.Name);
        _approvedRulesIni.Save(_rulesFilePath);

        if (target.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase))
        {
            SetRuleEnabled(target, false);
        }
    }

    public void DeleteRule(FirewallRuleModel target)
    {
        dynamic policy = GetPolicy();
        dynamic rules = policy.Rules;

        // Temporarily rename non-target rules that share the exact same Name
        var renamedRules = new List<(dynamic rule, string originalName)>();

        foreach (dynamic rule in rules)
        {
            if (string.Equals((string)(rule.Name ?? ""), target.Name, StringComparison.OrdinalIgnoreCase))
            {
                if (!RuleMatches(rule, target))
                {
                    string tempName = Guid.NewGuid().ToString("N");
                    rule.Name = tempName;
                    renamedRules.Add((rule, target.Name));
                }
            }
        }

        try
        {
            policy.Rules.Remove(target.Name);
        }
        finally
        {
            foreach (var item in renamedRules)
            {
                item.rule.Name = item.originalName;
            }
        }

        string section = GetSectionForDirection(target.Direction);
        _approvedRul
