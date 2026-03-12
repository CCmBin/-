using System.Text.RegularExpressions;
using LogAudit.Core.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace LogAudit.Core.Detector;

public class RuleEngine
{
    public List<DetectionRule> Rules { get; } = [];

    public static RuleEngine Load(string path)
    {
        var yaml = File.ReadAllText(path);
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var file = deserializer.Deserialize<RuleFile>(yaml);
        var engine = new RuleEngine();

        foreach (var ry in file.Rules ?? [])
        {
            if (string.IsNullOrEmpty(ry.Id) || ry.Patterns == null || ry.Patterns.Count == 0)
                continue;

            var rule = new DetectionRule
            {
                ID = ry.Id,
                Name = ry.Name ?? ry.Id,
                Category = ry.Category ?? "",
                Severity = ParseSeverity(ry.Severity)
            };

            foreach (var pat in ry.Patterns)
            {
                try
                {
                    rule.Patterns.Add(new Regex(pat, RegexOptions.Compiled | RegexOptions.IgnoreCase));
                }
                catch { /* skip invalid pattern */ }
            }

            if (rule.Patterns.Count > 0)
                engine.Rules.Add(rule);
        }

        return engine;
    }

    private static Severity ParseSeverity(string? s) => s?.ToLower() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        _ => Severity.Low
    };

    // YAML model
    private class RuleFile
    {
        public string? Version { get; set; }
        public List<RuleYaml>? Rules { get; set; }
    }

    private class RuleYaml
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public string? Category { get; set; }
        public string? Severity { get; set; }
        public List<string>? Patterns { get; set; }
    }
}
