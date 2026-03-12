using LogAudit.Core.Models;

namespace LogAudit.Core.Reporter;

public class AttackIP
{
    public string IP { get; set; } = "";
    public int Total { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public string First { get; set; } = "";
    public string Last { get; set; } = "";
    public DateTime LastTime { get; set; }
    public List<string> TopCategories { get; set; } = [];
    public string RiskLevel => Critical > 0 ? "严重" : High > 0 ? "高危" : Medium > 0 ? "中危" : "低危";
    public string RiskColor => Critical > 0 ? "#ff2255" : High > 0 ? "#ff7700" : Medium > 0 ? "#ffbb00" : "#33bbff";
}

public class RuleStat
{
    public string RuleID { get; set; } = "";
    public string RuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public string SevLabel { get; set; } = "";
    public string BarColor { get; set; } = "";
    public int Count { get; set; }
    public string Pct { get; set; } = "";
}

public class HitRow
{
    public string IP { get; set; } = "";
    public string TimeStr { get; set; } = "";
    public string Method { get; set; } = "";
    public int Status { get; set; }
    public string URI { get; set; } = "";
    public int Line { get; set; }
    public string Raw { get; set; } = "";
}

public class HitGroup
{
    public string RuleID { get; set; } = "";
    public string RuleName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public string SevLabel { get; set; } = "";
    public int HitCount { get; set; }
    public bool Truncated { get; set; }
    public List<HitRow> Hits { get; set; } = [];
}

public class UARow
{
    public string UA { get; set; } = "";
    public int Count { get; set; }
    public string ToolName { get; set; } = "";
}

public class AttackTimeline
{
    public string Hour { get; set; } = "";
    public int Count { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
}

public class CategoryTrend
{
    public string Category { get; set; } = "";
    public int Count { get; set; }
    public string Severity { get; set; } = "";
    public string Color { get; set; } = "";
}

public class SecurityResult
{
    public int TotalHits { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int UniqueIPs { get; set; }
    public int UniqueRules { get; set; }
    public int UniqueCategories { get; set; }
    public string RiskLevel { get; set; } = "";
    public string RiskColor { get; set; } = "";
    public string DateRange { get; set; } = "";

    public List<AttackIP> TopIPs { get; set; } = [];
    public List<RuleStat> RuleStats { get; set; } = [];
    public List<HitGroup> Groups { get; set; } = [];
    public List<UARow> TopUAs { get; set; } = [];
    public List<AttackTimeline> Timeline { get; set; } = [];
    public List<CategoryTrend> CategoryTrends { get; set; } = [];
}

public class SecurityReporter
{
    private readonly List<Hit> _hits = [];
    private readonly Dictionary<string, AttackIP> _ipMap = [];
    private readonly Dictionary<string, RuleStat> _ruleMap = [];
    private readonly Dictionary<string, HitGroup> _grpMap = [];
    private readonly Dictionary<string, int> _uaMap = [];
    private readonly Dictionary<string, Dictionary<string, int>> _ipCategories = [];

    public void Add(Hit h)
    {
        _hits.Add(h);

        // IP tracking
        if (!_ipMap.TryGetValue(h.IP, out var ip))
        {
            ip = new AttackIP
            {
                IP = h.IP,
                First = h.Time != default ? h.Time.ToString("MM-dd HH:mm") : "",
                Last = h.Time != default ? h.Time.ToString("MM-dd HH:mm") : "",
                LastTime = h.Time
            };
            _ipMap[h.IP] = ip;
        }
        ip.Total++;
        if (h.Time != default && h.Time > ip.LastTime)
        {
            ip.LastTime = h.Time;
            ip.Last = h.Time.ToString("MM-dd HH:mm");
        }
        switch (h.Rule.Severity)
        {
            case Severity.Critical: ip.Critical++; break;
            case Severity.High: ip.High++; break;
            case Severity.Medium: ip.Medium++; break;
            case Severity.Low: ip.Low++; break;
        }

        if (!_ipCategories.ContainsKey(h.IP)) _ipCategories[h.IP] = [];
        _ipCategories[h.IP].TryAdd(h.Rule.Category, 0);
        _ipCategories[h.IP][h.Rule.Category]++;

        // Rule stats
        if (!_ruleMap.TryGetValue(h.Rule.ID, out var rs))
        {
            rs = new RuleStat
            {
                RuleID = h.Rule.ID, RuleName = h.Rule.Name,
                Category = h.Rule.Category,
                Severity = h.Rule.Severity.ToString().ToLower(),
                SevLabel = SeverityHelper.Label(h.Rule.Severity),
                BarColor = SeverityHelper.Color(h.Rule.Severity)
            };
            _ruleMap[h.Rule.ID] = rs;
        }
        rs.Count++;

        // Hit groups
        if (!_grpMap.TryGetValue(h.Rule.ID, out var grp))
        {
            grp = new HitGroup
            {
                RuleID = h.Rule.ID, RuleName = h.Rule.Name,
                Category = h.Rule.Category,
                Severity = h.Rule.Severity.ToString().ToLower(),
                SevLabel = SeverityHelper.Label(h.Rule.Severity)
            };
            _grpMap[h.Rule.ID] = grp;
        }
        grp.HitCount++;
        if (grp.Hits.Count < 200)
        {
            grp.Hits.Add(new HitRow
            {
                IP = h.IP,
                TimeStr = h.Time != default ? h.Time.ToString("MM-dd HH:mm:ss") : "",
                Method = h.Method, Status = h.Status,
                URI = Clip(h.URI, 100),
                Line = h.LineNum,
                Raw = Clip(h.Raw, 200)
            });
        }

        if (!string.IsNullOrEmpty(h.UA) && h.UA != "-")
        {
            _uaMap.TryAdd(h.UA, 0); _uaMap[h.UA]++;
        }
    }

    public SecurityResult Build()
    {
        var sr = new SecurityResult
        {
            TotalHits = _hits.Count,
            UniqueIPs = _ipMap.Count,
            UniqueRules = _ruleMap.Count
        };

        var cats = new HashSet<string>();
        foreach (var h in _hits)
        {
            switch (h.Rule.Severity)
            {
                case Severity.Critical: sr.CriticalCount++; break;
                case Severity.High: sr.HighCount++; break;
                case Severity.Medium: sr.MediumCount++; break;
                case Severity.Low: sr.LowCount++; break;
            }
            cats.Add(h.Rule.Category);
        }
        sr.UniqueCategories = cats.Count;

        // Risk level
        if (sr.CriticalCount > 0) { sr.RiskLevel = "严重威胁"; sr.RiskColor = "#ff2255"; }
        else if (sr.HighCount > 0) { sr.RiskLevel = "高危威胁"; sr.RiskColor = "#ff7700"; }
        else if (sr.MediumCount > 0) { sr.RiskLevel = "中危威胁"; sr.RiskColor = "#ffbb00"; }
        else { sr.RiskLevel = "低危"; sr.RiskColor = "#33bbff"; }

        // Date range
        var validTimes = _hits.Where(h => h.Time != default).Select(h => h.Time).ToList();
        if (validTimes.Count > 0)
            sr.DateRange = $"{validTimes.Min():yyyy-MM-dd HH:mm} 至 {validTimes.Max():yyyy-MM-dd HH:mm}";

        // Top IPs
        sr.TopIPs = _ipMap.Values
            .OrderByDescending(x => x.Total)
            .Take(20)
            .ToList();
        foreach (var ip in sr.TopIPs)
        {
            if (_ipCategories.TryGetValue(ip.IP, out var catMap))
                ip.TopCategories = catMap.OrderByDescending(x => x.Value).Take(3).Select(x => x.Key).ToList();
        }

        // Rule stats
        var total = _hits.Count;
        sr.RuleStats = _ruleMap.Values
            .Select(rs => { rs.Pct = total > 0 ? $"{(double)rs.Count / total * 100:F1}" : "0.0"; return rs; })
            .OrderByDescending(rs => rs.Count)
            .ToList();

        // Groups sorted by severity then count
        sr.Groups = _grpMap.Values
            .Select(g => { g.Truncated = g.HitCount > g.Hits.Count; return g; })
            .OrderByDescending(g => SeverityHelper.Rank(Enum.Parse<Severity>(g.Severity, true)))
            .ThenByDescending(g => g.HitCount)
            .ToList();

        // UAs
        sr.TopUAs = _uaMap
            .OrderByDescending(x => x.Value)
            .Take(30)
            .Select(x => new UARow { UA = x.Key, Count = x.Value, ToolName = UaClass(x.Key) })
            .ToList();

        // Attack timeline
        var hourMap = new Dictionary<string, (int total, int crit, int high)>();
        foreach (var h in _hits.Where(h => h.Time != default))
        {
            var key = h.Time.ToString("MM-dd HH:00");
            hourMap.TryAdd(key, (0, 0, 0));
            var (t, c, hi) = hourMap[key];
            t++;
            if (h.Rule.Severity == Severity.Critical) c++;
            if (h.Rule.Severity == Severity.High) hi++;
            hourMap[key] = (t, c, hi);
        }
        sr.Timeline = hourMap.OrderBy(x => x.Key)
            .Select(x => new AttackTimeline { Hour = x.Key, Count = x.Value.total, Critical = x.Value.crit, High = x.Value.high })
            .ToList();

        // Category trends
        var catMap2 = new Dictionary<string, (int count, Severity maxSev)>();
        foreach (var h in _hits)
        {
            catMap2.TryAdd(h.Rule.Category, (0, Severity.Low));
            var (c, s) = catMap2[h.Rule.Category];
            c++;
            if (h.Rule.Severity > s) s = h.Rule.Severity;
            catMap2[h.Rule.Category] = (c, s);
        }
        sr.CategoryTrends = catMap2
            .OrderByDescending(x => x.Value.count)
            .Select(x => new CategoryTrend
            {
                Category = x.Key, Count = x.Value.count,
                Severity = x.Value.maxSev.ToString().ToLower(),
                Color = SeverityHelper.Color(x.Value.maxSev)
            })
            .ToList();

        return sr;
    }

    private static string Clip(string s, int n)
    {
        s = s.Trim();
        return s.Length <= n ? s : s[..n] + "…";
    }

    private static string UaClass(string ua)
    {
        var l = ua.ToLower();
        if (l.Contains("sqlmap")) return "sqlmap";
        if (l.Contains("nmap")) return "Nmap";
        if (l.Contains("nuclei")) return "Nuclei";
        if (l.Contains("nikto")) return "Nikto";
        if (l.Contains("acunetix") || l.Contains("awvs")) return "AWVS";
        if (l.Contains("burp")) return "Burp Suite";
        if (l.Contains("nessus")) return "Nessus";
        if (l.Contains("masscan")) return "Masscan";
        if (l.Contains("dirbuster") || l.Contains("gobuster") || l.Contains("ffuf")) return "目录爆破";
        if (l.Contains("python")) return "Python脚本";
        if (l.Contains("go-http")) return "Go脚本";
        if (l.Contains("curl")) return "curl";
        if (l.Contains("wget")) return "wget";
        if (l.Contains("bot") || l.Contains("spider")) return "爬虫/Bot";
        return "其他工具";
    }
}
