using System.Reflection;
using System.Text;
using System.Text.Json;

namespace LogAudit.Core.Reporter;

public static class SecurityReportGenerator
{
    public static string Generate(SecurityResult sr, string reportTime, string fileName, string duration)
    {
        var shell = LoadTemplate("security.html");
        var json  = BuildJson(sr);
        return shell
            .Replace("__TITLE__",        HE(fileName))
            .Replace("__FILE_NAME__",    HE(fileName))
            .Replace("__REPORT_TIME__",  HE(reportTime))
            .Replace("__DURATION__",     HE(duration))
            .Replace("__RISK_LEVEL__",   HE(sr.RiskLevel))
            .Replace("__RISK_COLOR__",   sr.RiskColor)
            .Replace("__JSON__",         json)
            .Replace("__SEC_OVERVIEW__", BuildOverview(sr))
            .Replace("__SEC_TIMELINE__", BuildTimeline())
            .Replace("__SEC_IPS__",      BuildIPs(sr))
            .Replace("__SEC_RULES__",    BuildRules(sr))
            .Replace("__SEC_HITS__",     BuildHits(sr))
            .Replace("__SEC_TOOLS__",    BuildTools(sr));
    }

    // ── template loader ───────────────────────────────────────────────────────
    private static string LoadTemplate(string name)
    {
        var dir = AppDomain.CurrentDomain.BaseDirectory;
        foreach (var c in new[]{
            Path.Combine(dir,"Core","Reporter","Templates",name),
            Path.Combine(dir,name),
            Path.Combine("Core","Reporter","Templates",name), name })
            if (File.Exists(c)) return File.ReadAllText(c, Encoding.UTF8);
        var asm = Assembly.GetExecutingAssembly();
        using var s = asm.GetManifestResourceStream("LogAudit.Core.Reporter.Templates."+name);
        if (s != null) { using var r = new StreamReader(s); return r.ReadToEnd(); }
        throw new FileNotFoundException("Template not found: "+name);
    }

    // ── JSON ─────────────────────────────────────────────────────────────────
    private static string BuildJson(SecurityResult sr)
    {
        var sevs = new List<object>();
        if(sr.CriticalCount>0) sevs.Add(new{name="严重",value=sr.CriticalCount});
        if(sr.HighCount>0)     sevs.Add(new{name="高危",value=sr.HighCount});
        if(sr.MediumCount>0)   sevs.Add(new{name="中危",value=sr.MediumCount});
        if(sr.LowCount>0)      sevs.Add(new{name="低危",value=sr.LowCount});

        int maxCat = sr.CategoryTrends.Count>0 ? sr.CategoryTrends.Max(x=>x.Count) : 1;
        var radar = sr.CategoryTrends.Take(8).Select(x=>new{n=x.Category,v=x.Count,m=maxCat});
        var tl    = sr.Timeline.Select(x=>new{t=x.Hour,c=x.Count,cr=x.Critical,hi=x.High});
        var ips   = sr.TopIPs.Select(x=>new{ip=x.IP,total=x.Total,cr=x.Critical,hi=x.High,me=x.Medium,lo=x.Low});
        var rules = sr.RuleStats.Select(x=>new{name=x.RuleName,value=x.Count});
        var uaT   = sr.TopUAs.GroupBy(x=>x.ToolName).OrderByDescending(g=>g.Sum(x=>x.Count)).Take(10)
                      .Select(g=>new{name=g.Key,value=g.Sum(x=>x.Count)});
        var uaB   = sr.TopUAs.Take(10).Select(x=>new{
            name=x.UA.Length>50?x.UA[..48]+"\u2026":x.UA, value=x.Count});
        var cats  = sr.CategoryTrends.Select(x=>new{name=x.Category,value=x.Count});
        return JsonSerializer.Serialize(new{sevs,cats,radar,tl,ips,rules,uaT,uaB});
    }

    // ── Overview ─────────────────────────────────────────────────────────────
    private static string BuildOverview(SecurityResult sr)
    {
        var sb = new StringBuilder();
        // KPIs
        sb.Append("<div class=\"kpi-grid\">");
        K(sb,"critical",Fmt(sr.TotalHits),         "安全告警总数","var(--critical)");
        K(sb,"critical",sr.CriticalCount.ToString(),"严重威胁",   "var(--critical)");
        K(sb,"high",    sr.HighCount.ToString(),    "高危威胁",   "var(--high)");
        K(sb,"medium",  sr.MediumCount.ToString(),  "中危威胁",   "var(--medium)");
        K(sb,"low",     sr.LowCount.ToString(),     "低危告警",   "var(--low)");
        K(sb,"blue",    sr.UniqueIPs.ToString(),    "攻击IP数",   "var(--accent)");
        K(sb,"blue",    sr.UniqueRules.ToString(),  "命中规则数", "var(--accent)");
        K(sb,"blue",    sr.UniqueCategories.ToString(),"攻击类型","var(--accent)");
        sb.Append("</div>");

        if (!string.IsNullOrEmpty(sr.DateRange))
            sb.Append("<p style=\"color:var(--text2);font-size:12px;margin-bottom:16px\">📅 攻击时间范围: ")
              .Append(HE(sr.DateRange)).Append("</p>");

        // 2 pie charts
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("🎯 威胁等级分布","<div id=\"ch-sev\" class=\"ch300\"></div>"));
        sb.Append(Card("🗂 攻击类型分布","<div id=\"ch-cats\" class=\"ch300\"></div>"));
        sb.Append("</div>");

        // Radar + category table
        sb.Append("<div class=\"grid g2\">");
        sb.Append(Card("📡 攻击类型雷达图","<div id=\"ch-radar\" class=\"ch300\"></div>"));

        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>攻击类型</th><th class=\"num\">数量</th><th>最高等级</th><th>占比</th></tr>");
        foreach (var ct in sr.CategoryTrends)
        {
            double pct = sr.TotalHits>0?(double)ct.Count/sr.TotalHits*100:0;
            tbl.Append("<tr><td>").Append(HE(ct.Category))
               .Append("</td><td class=\"num\">").Append(ct.Count)
               .Append("</td><td><span class=\"sev sev-").Append(ct.Severity).Append("\">")
               .Append(Models.SeverityHelper.Label(Enum.Parse<Models.Severity>(ct.Severity,true)))
               .Append("</span></td><td>"); Bar(tbl,pct,ct.Color); tbl.Append("</td></tr>");
        }
        tbl.Append("</table>");
        sb.Append(Card("📊 攻击类型详情","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        sb.Append("</div>");
        return sb.ToString();
    }

    // ── Timeline ─────────────────────────────────────────────────────────────
    private static string BuildTimeline()
        => Card("📈 攻击时间线（按小时）","<div id=\"ch-timeline\" class=\"ch360\"></div>");

    // ── IPs ──────────────────────────────────────────────────────────────────
    private static string BuildIPs(SecurityResult sr)
    {
        var sb = new StringBuilder();
        // Charts
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("🏆 Top 攻击IP 告警量","<div id=\"ch-atk-ips\" class=\"ch420\"></div>"));
        sb.Append(Card("🧱 IP 威胁组成（堆叠）","<div id=\"ch-ip-stack\" class=\"ch420\"></div>"));
        sb.Append("</div>");
        // Table
        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>IP</th><th class=\"num\">告警总数</th><th class=\"num\">严重</th><th class=\"num\">高危</th><th class=\"num\">中危</th><th class=\"num\">低危</th><th>首次</th><th>末次</th></tr>");
        int i=1;
        foreach (var ip in sr.TopIPs)
            tbl.Append("<tr><td style=\"color:var(--text3)\">").Append(i++)
               .Append("</td><td class=\"mono\" style=\"color:var(--critical)\">").Append(HE(ip.IP))
               .Append("</td><td class=\"num\" style=\"font-weight:600\">").Append(ip.Total)
               .Append("</td><td class=\"num\" style=\"color:var(--critical)\">").Append(ip.Critical)
               .Append("</td><td class=\"num\" style=\"color:var(--high)\">").Append(ip.High)
               .Append("</td><td class=\"num\" style=\"color:var(--medium)\">").Append(ip.Medium)
               .Append("</td><td class=\"num\" style=\"color:var(--low)\">").Append(ip.Low)
               .Append("</td><td class=\"mono\" style=\"font-size:11px;color:var(--text2)\">").Append(HE(ip.First))
               .Append("</td><td class=\"mono\" style=\"font-size:11px;color:var(--text2)\">").Append(HE(ip.Last))
               .Append("</td></tr>");
        tbl.Append("</table>");
        sb.Append(Card("🌐 攻击IP详情","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        return sb.ToString();
    }

    // ── Rules ────────────────────────────────────────────────────────────────
    private static string BuildRules(SecurityResult sr)
    {
        var sb = new StringBuilder();
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("📊 规则命中排行","<div id=\"ch-rules\" class=\"ch420\"></div>"));

        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>规则名</th><th>类别</th><th>等级</th><th class=\"num\">次数</th><th>占比</th></tr>");
        int i=1;
        foreach (var r in sr.RuleStats)
        {
            double pct=0; double.TryParse(r.Pct,out pct);
            tbl.Append("<tr><td>").Append(i++)
               .Append("</td><td>").Append(HE(r.RuleName))
               .Append("<br><span style=\"font-size:10px;color:var(--text3)\">").Append(HE(r.RuleID)).Append("</span>")
               .Append("</td><td style=\"color:var(--text2)\">").Append(HE(r.Category))
               .Append("</td><td><span class=\"sev sev-").Append(r.Severity).Append("\">")
               .Append(HE(r.SevLabel)).Append("</span>")
               .Append("</td><td class=\"num\" style=\"font-weight:600\">").Append(r.Count)
               .Append("</td><td>"); Bar(tbl,pct,r.BarColor); tbl.Append("</td></tr>");
        }
        tbl.Append("</table>");
        sb.Append(Card("📋 规则统计详情","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        sb.Append("</div>");
        return sb.ToString();
    }

    // ── Hits ─────────────────────────────────────────────────────────────────
    private static string BuildHits(SecurityResult sr)
    {
        var sb = new StringBuilder();
        sb.Append("<p style=\"color:var(--text2);font-size:12px;margin-bottom:16px\">点击各规则展开命中详情（每规则最多 200 条）</p>");
        foreach (var g in sr.Groups)
        {
            var rows = new StringBuilder();
            foreach (var h in g.Hits)
            {
                var sc = h.Status>=500?"sev-critical":h.Status>=400?"sev-high":h.Status>=300?"sev-medium":"sev-low";
                rows.Append("<tr><td class=\"mono\">").Append(HE(h.IP))
                    .Append("</td><td class=\"mono\" style=\"font-size:11px;color:var(--text2)\">").Append(HE(h.TimeStr))
                    .Append("</td><td>").Append(HE(h.Method))
                    .Append("</td><td><span class=\"sev ").Append(sc).Append("\">").Append(h.Status).Append("</span>")
                    .Append("</td><td class=\"mono\" style=\"font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\" title=\"")
                    .Append(HE(h.URI)).Append("\">").Append(HE(h.URI))
                    .Append("</td><td class=\"num\" style=\"color:var(--text2)\">").Append(h.Line).Append("</td></tr>");
            }
            sb.Append("<div class=\"grp\">")
              .Append("<div class=\"grp-hd\" onclick=\"toggleGrp(this)\">")
              .Append("<span class=\"grp-arrow\">&#x25B6;</span>")
              .Append("<span class=\"sev sev-").Append(g.Severity).Append("\">").Append(HE(g.SevLabel)).Append("</span>")
              .Append("<span class=\"rule-name\">").Append(HE(g.RuleName)).Append("</span>")
              .Append("<span style=\"font-size:11px;color:var(--text2)\">[").Append(HE(g.Category)).Append("]</span>")
              .Append("<span class=\"count\">").Append(g.HitCount).Append(" 次命中</span>")
              .Append("</div><div class=\"grp-bd\">");
            if (g.Truncated)
                sb.Append("<p style=\"padding:6px 16px;color:var(--text2);font-size:11px\">仅展示前 ")
                  .Append(g.Hits.Count).Append(" 条，共 ").Append(g.HitCount).Append(" 条</p>");
            sb.Append("<table class=\"tbl\"><tr><th>IP</th><th>时间</th><th>方法</th><th>状态</th><th>URI</th><th>行号</th></tr>")
              .Append(rows).Append("</table></div></div>");
        }
        return sb.ToString();
    }

    // ── Tools ────────────────────────────────────────────────────────────────
    private static string BuildTools(SecurityResult sr)
    {
        var sb = new StringBuilder();
        // Two charts side by side — pie gets fixed height, bar auto-sizes via JS
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("🔧 攻击工具类型分布","<div id=\"ch-ua-type\" class=\"ch360\"></div>"));
        sb.Append(Card("🔍 攻击 User-Agent Top 10","<div id=\"ch-ua-bar\" class=\"ch360\"></div>"));
        sb.Append("</div>");

        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>User-Agent</th><th>工具识别</th><th class=\"num\">次数</th></tr>");
        int i=1;
        foreach (var u in sr.TopUAs)
            tbl.Append("<tr><td>").Append(i++)
               .Append("</td><td class=\"mono\" style=\"font-size:11px;max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\" title=\"")
               .Append(HE(u.UA)).Append("\">").Append(HE(u.UA))
               .Append("</td><td style=\"color:var(--high)\">").Append(HE(u.ToolName))
               .Append("</td><td class=\"num\" style=\"font-weight:600\">").Append(u.Count).Append("</td></tr>");
        tbl.Append("</table>");
        sb.Append(Card("📋 完整 User-Agent 列表","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        return sb.ToString();
    }

    // ── helpers ────────────────────────────────────────────────────────────────
    private static string Card(string title, string body)
        => "<div class=\"card\"><div class=\"card-hd\"><h3>"+title+"</h3></div><div class=\"card-bd\">"+body+"</div></div>";

    private static void K(StringBuilder sb,string cls,string val,string lbl,string color)
    {
        sb.Append("<div class=\"kpi ").Append(cls).Append("\">")
          .Append("<div class=\"kpi-val\" style=\"color:").Append(color).Append("\">").Append(HE(val)).Append("</div>")
          .Append("<div class=\"kpi-lbl\">").Append(HE(lbl)).Append("</div></div>");
    }
    private static void Bar(StringBuilder sb,double pct,string color)
    {
        int w=Math.Min(100,(int)pct);
        sb.Append("<div class=\"bar-wrap\"><div class=\"bar-bg\"><div class=\"bar-fill\" style=\"width:")
          .Append(w).Append("%;background:").Append(color)
          .Append("\"></div></div><span style=\"font-size:11px;color:var(--text2)\">")
          .Append(pct.ToString("F1")).Append("%</span></div>");
    }
    private static string Fmt(int n)
    {
        if(n<1000)return n.ToString();
        var s=n.ToString();var b=new StringBuilder();
        for(int i=0;i<s.Length;i++){if(i>0&&(s.Length-i)%3==0)b.Append(',');b.Append(s[i]);}
        return b.ToString();
    }
    private static string HE(string s) =>
        s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace("\"","&quot;");
}
