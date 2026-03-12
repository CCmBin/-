using System.Reflection;
using System.Text;
using System.Text.Json;
using LogAudit.Core.Analyzer;

namespace LogAudit.Core.Reporter;

public static class TrafficReportGenerator
{
    public static string Generate(AnalysisResult ar, string reportTime, string fileName, string duration)
    {
        var shell = LoadTemplate("traffic.html");
        var json  = BuildJson(ar);
        return shell
            .Replace("__TITLE__",        HE(fileName))
            .Replace("__FILE_NAME__",    HE(fileName))
            .Replace("__REPORT_TIME__",  HE(reportTime))
            .Replace("__DURATION__",     HE(duration))
            .Replace("__JSON__",         json)
            .Replace("__KPI__",          BuildKpi(ar))
            .Replace("__SEC_OVERVIEW__", BuildOverview(ar))
            .Replace("__SEC_TRAFFIC__",  BuildTraffic())
            .Replace("__SEC_IPS__",      BuildIPs(ar))
            .Replace("__SEC_PAGES__",    BuildPages(ar))
            .Replace("__SEC_CLIENTS__",  BuildClients())
            .Replace("__SEC_ERRORS__",   BuildErrors(ar));
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
    private static string BuildJson(AnalysisResult ar)
    {
        var d   = ar.DailyStats.Select(x => new { t=x.T, c=x.C });
        var h   = ar.HourlyStats.Select(x => new { t=x.T, c=x.C });
        var sp  = ar.StatusStats.GroupBy(x => x.Code>=500?"5xx":x.Code>=400?"4xx":x.Code>=300?"3xx":"2xx")
                    .Select(g => new { name=g.Key, value=g.Sum(x=>x.Count) });
        var mt  = ar.MethodStats.OrderByDescending(x=>x.Value).Take(10).Select(x=>new{k=x.Key,v=x.Value});
        var pt  = ar.ProtoStats.Select(x=>new{k=x.Key,v=x.Value});
        var ex  = ar.ExtStats.OrderByDescending(x=>x.Value).Take(15)
                    .Select(x=>new{k=string.IsNullOrEmpty(x.Key)?"(none)":x.Key,v=x.Value});
        var ips = ar.TopIPs.Select(x=>new{
            ip=x.IP, req=x.Requests, bytes=x.Bytes,
            err=x.Status4xx+x.Status5xx,
            errRate=x.Requests>0?(double)(x.Status4xx+x.Status5xx)/x.Requests*100:0.0});
        var pgs = ar.TopPages.Select(x=>new{p=x.Path,r=x.Requests,b=x.Bytes});
        var sts = ar.TopStatic.Select(x=>new{p=x.Path,r=x.Requests,b=x.Bytes});
        var refs= ar.TopReferers.Take(15).Select(x=>new{k=x.Key,v=x.Value});
        var br  = ar.BrowserStats.Select(x=>new{k=x.Key,v=x.Value});
        var os  = ar.OSStats.Select(x=>new{k=x.Key,v=x.Value});
        var hod = ar.HourOfDayStats.Select(x=>new{k=x.Key,v=x.Value});
        var dow = ar.DayOfWeekStats.Select(x=>new{k=x.Key,v=x.Value});
        return JsonSerializer.Serialize(new{d,h,sp,mt,pt,ex,ips,pgs,sts,refs,br,os,hod,dow});
    }

    // ── KPI ──────────────────────────────────────────────────────────────────
    private static string BuildKpi(AnalysisResult ar)
    {
        var sb = new StringBuilder("<div class=\"kpi-grid\">");
        K(sb,"blue",  Fmt(ar.TotalRequests),       "总请求数","");
        K(sb,"green", Fmt(ar.TotalIPs),             "独立IP数","");
        K(sb,"orange",FB(ar.TotalBytes),            "总流量","");
        K(sb,"yellow",ar.AvgRequestSize,            "平均响应","");
        K(sb,"red",   ar.ErrorRate.ToString("F1")+"%","错误率",ar.Status4xx+ar.Status5xx+" 次错误");
        K(sb,"purple",ar.BotRate.ToString("F1")+"%","Bot流量","");
        K(sb,"blue",  ar.MobileRate.ToString("F1")+"%","移动端","");
        K(sb,"green", ar.UniquePaths.ToString(),   "独立页面","");
        return sb.Append("</div>").ToString();
    }
    private static void K(StringBuilder sb,string cls,string val,string lbl,string sub)
    {
        sb.Append("<div class=\"kpi ").Append(cls).Append("\">")
          .Append("<div class=\"kpi-val\">").Append(HE(val)).Append("</div>")
          .Append("<div class=\"kpi-lbl\">").Append(HE(lbl)).Append("</div>");
        if (!string.IsNullOrEmpty(sub))
            sb.Append("<div class=\"kpi-sub\">").Append(HE(sub)).Append("</div>");
        sb.Append("</div>");
    }

    // ── Sections ─────────────────────────────────────────────────────────────
    private static string BuildOverview(AnalysisResult ar)
    {
        var sb = new StringBuilder();
        // Status code distribution + table
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("📊 状态码分布","<div id=\"ch-status-pie\" class=\"ch300\"></div>"));
        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>状态码</th><th>描述</th><th class=\"num\">次数</th><th>占比</th></tr>");
        foreach (var s in ar.StatusStats.OrderByDescending(x=>x.Count))
        {
            var cls = s.Code>=500?"s5":s.Code>=400?"s4":s.Code>=300?"s3":"s2";
            double pct = ar.TotalRequests>0?(double)s.Count/ar.TotalRequests*100:0;
            tbl.Append("<tr><td><span class=\"badge ").Append(cls).Append("\">").Append(s.Code)
               .Append("</span></td><td style=\"color:var(--text2)\">").Append(HE(s.Desc))
               .Append("</td><td class=\"num\">").Append(Fmt(s.Count))
               .Append("</td><td>"); Bar(tbl,pct,s.Code>=500?"#f85149":s.Code>=400?"#d29922":"#3fb950");
            tbl.Append("</td></tr>");
        }
        tbl.Append("</table>");
        sb.Append(Card("📋 状态码详情","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        sb.Append("</div>");
        // Hour of day + day of week
        sb.Append("<div class=\"grid g2\">");
        sb.Append(Card("🕐 小时分布（全天）","<div id=\"ch-hod\" class=\"ch300\"></div>"));
        sb.Append(Card("📅 星期分布","<div id=\"ch-dow\" class=\"ch300\"></div>"));
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string BuildTraffic()
    {
        var sb = new StringBuilder();
        sb.Append(Card("📈 每日流量趋势","<div id=\"ch-daily\" class=\"ch360\"></div>"));
        sb.Append("<div style=\"margin-top:16px\">");
        sb.Append(Card("🕐 小时流量趋势（精确）","<div id=\"ch-hourly\" class=\"ch360\"></div>"));
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string BuildIPs(AnalysisResult ar)
    {
        var sb = new StringBuilder();
        // Charts
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("🏆 Top IP 请求量","<div id=\"ch-top-ip\" class=\"ch420\"></div>"));
        sb.Append(Card("🌍 IP 分布","<div id=\"ch-ip-dist\" class=\"ch420\"></div>"));
        sb.Append("</div>");
        // Table
        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>IP</th><th class=\"num\">请求</th><th class=\"num\">流量</th><th class=\"num\">4xx</th><th class=\"num\">5xx</th><th>滥用评分</th><th>首次</th><th>末次</th></tr>");
        int i=1;
        foreach (var ip in ar.TopIPs)
        {
            double er = ip.Requests>0?(double)(ip.Status4xx+ip.Status5xx)/ip.Requests*100:0;
            string abuseColor = er>50?"var(--red)":er>20?"var(--yellow)":"var(--green)";
            tbl.Append("<tr><td style=\"color:var(--text3)\">").Append(i++)
               .Append("</td><td class=\"mono\" style=\"color:var(--accent)\">").Append(HE(ip.IP))
               .Append("</td><td class=\"num\">").Append(Fmt(ip.Requests))
               .Append("</td><td class=\"num\">").Append(FB(ip.Bytes))
               .Append("</td><td class=\"num\" style=\"color:var(--yellow)\">").Append(ip.Status4xx)
               .Append("</td><td class=\"num\" style=\"color:var(--red)\">").Append(ip.Status5xx)
               .Append("</td><td><span style=\"color:").Append(abuseColor).Append("\">")
               .Append(ip.AbuseScore).Append("</span></td>")
               .Append("<td class=\"mono\" style=\"color:var(--text2);font-size:11px\">").Append(HE(ip.FirstSeen))
               .Append("</td><td class=\"mono\" style=\"color:var(--text2);font-size:11px\">").Append(HE(ip.LastSeen))
               .Append("</td></tr>");
        }
        tbl.Append("</table>");
        sb.Append(Card("🌐 IP 详细统计","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        return sb.ToString();
    }

    private static string BuildPages(AnalysisResult ar)
    {
        var sb = new StringBuilder();
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("📄 热门页面 Top 12","<div id=\"ch-pages\" class=\"ch420\"></div>"));
        sb.Append(Card("🗂 热门静态资源 Top 12","<div id=\"ch-static\" class=\"ch420\"></div>"));
        sb.Append("</div>");

        // Top pages table
        var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>路径</th><th class=\"num\">请求</th><th class=\"num\">流量</th><th class=\"num\">错误率</th><th class=\"num\">独立IP</th></tr>");
        int i=1;
        foreach (var p in ar.TopPages)
        {
            string errColor = p.ErrorRate>20?"var(--red)":p.ErrorRate>5?"var(--yellow)":"var(--text2)";
            tbl.Append("<tr><td style=\"color:var(--text3)\">").Append(i++)
               .Append("</td><td class=\"mono\" style=\"font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\" title=\"")
               .Append(HE(p.Path)).Append("\">").Append(HE(p.Path))
               .Append("</td><td class=\"num\">").Append(Fmt(p.Requests))
               .Append("</td><td class=\"num\">").Append(FB(p.Bytes))
               .Append("</td><td class=\"num\" style=\"color:").Append(errColor).Append("\">")
               .Append(p.ErrorRate.ToString("F1")).Append("%")
               .Append("</td><td class=\"num\">").Append(p.UniqueIPs).Append("</td></tr>");
        }
        tbl.Append("</table>");
        sb.Append(Card("📄 页面详情","<div style=\"overflow-x:auto\">"+tbl+"</div>"));

        // Referrers
        if (ar.TopReferers.Any())
        {
            sb.Append("<div style=\"margin-top:16px\">");
            sb.Append(Card("🔗 来源域名","<div id=\"ch-referer\" class=\"ch300\"></div>"));
            sb.Append("</div>");
        }

        // Largest
        if (ar.LargestRequests.Any())
        {
            var tbl2 = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>路径</th><th class=\"num\">平均大小</th><th class=\"num\">请求数</th></tr>");
            i=1;
            foreach (var p in ar.LargestRequests.Take(15))
                tbl2.Append("<tr><td>").Append(i++).Append("</td><td class=\"mono\" style=\"font-size:11px\">")
                    .Append(HE(p.Path)).Append("</td><td class=\"num\">").Append(FB(p.AvgSize))
                    .Append("</td><td class=\"num\">").Append(p.Count).Append("</td></tr>");
            tbl2.Append("</table>");
            sb.Append("<div style=\"margin-top:16px\">");
            sb.Append(Card("📦 最大响应页面","<div style=\"overflow-x:auto\">"+tbl2+"</div>"));
            sb.Append("</div>");
        }
        return sb.ToString();
    }

    // Clients section: charts only — data populated by JS
    private static string BuildClients()
    {
        var sb = new StringBuilder();
        sb.Append("<div class=\"grid g2\" style=\"margin-bottom:16px\">");
        sb.Append(Card("🖥 浏览器分布","<div id=\"ch-browser\" class=\"ch300\"></div>"));
        sb.Append(Card("💻 操作系统分布","<div id=\"ch-os\" class=\"ch300\"></div>"));
        sb.Append("</div>");
        sb.Append("<div class=\"grid g3\">");
        sb.Append(Card("⚡ 请求方法","<div id=\"ch-method\" class=\"ch300\"></div>"));
        sb.Append(Card("🔗 协议版本","<div id=\"ch-proto\" class=\"ch300\"></div>"));
        sb.Append(Card("📎 文件扩展名","<div id=\"ch-ext\" class=\"ch300\"></div>"));
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string BuildErrors(AnalysisResult ar)
    {
        var sb = new StringBuilder();
        var errStats = ar.StatusStats.Where(x=>x.Code>=400).OrderByDescending(x=>x.Count).ToList();
        if (errStats.Any())
        {
            var tbl = new StringBuilder("<table class=\"tbl\"><tr><th>状态码</th><th>描述</th><th class=\"num\">次数</th><th>占比</th></tr>");
            foreach (var s in errStats)
            {
                double pct = ar.TotalRequests>0?(double)s.Count/ar.TotalRequests*100:0;
                string cls = s.Code>=500?"s5":"s4";
                tbl.Append("<tr><td><span class=\"badge ").Append(cls).Append("\">").Append(s.Code)
                   .Append("</span></td><td style=\"color:var(--text2)\">").Append(HE(s.Desc))
                   .Append("</td><td class=\"num\">").Append(Fmt(s.Count))
                   .Append("</td><td>"); Bar(tbl,pct,"#f85149"); tbl.Append("</td></tr>");
            }
            tbl.Append("</table>");
            sb.Append(Card("❌ 错误状态码统计","<div style=\"overflow-x:auto\">"+tbl+"</div>"));
        }

        var highErr = ar.TopPages.Where(x=>x.ErrorRate>0).OrderByDescending(x=>x.ErrorRate).Take(20).ToList();
        if (highErr.Any())
        {
            var tbl2 = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>路径</th><th class=\"num\">请求</th><th class=\"num\">错误率</th></tr>");
            int i=1;
            foreach (var p in highErr)
                tbl2.Append("<tr><td>").Append(i++).Append("</td><td class=\"mono\" style=\"font-size:11px\">")
                    .Append(HE(p.Path)).Append("</td><td class=\"num\">").Append(Fmt(p.Requests))
                    .Append("</td><td class=\"num\" style=\"color:var(--red)\">")
                    .Append(p.ErrorRate.ToString("F1")).Append("%</td></tr>");
            tbl2.Append("</table>");
            sb.Append("<div style=\"margin-top:16px\">");
            sb.Append(Card("🔥 高错误率页面","<div style=\"overflow-x:auto\">"+tbl2+"</div>"));
            sb.Append("</div>");
        }

        if (ar.DeadLinks.Any())
        {
            var tbl3 = new StringBuilder("<table class=\"tbl\"><tr><th>#</th><th>路径</th><th class=\"num\">404次数</th></tr>");
            int i=1;
            foreach (var d in ar.DeadLinks.Take(30))
                tbl3.Append("<tr><td>").Append(i++).Append("</td><td class=\"mono\" style=\"font-size:11px\">")
                    .Append(HE(d.Path)).Append("</td><td class=\"num\" style=\"color:var(--yellow)\">")
                    .Append(d.Count).Append("</td></tr>");
            tbl3.Append("</table>");
            sb.Append("<div style=\"margin-top:16px\">");
            sb.Append(Card("🚫 死链 Top 30","<div style=\"overflow-x:auto\">"+tbl3+"</div>"));
            sb.Append("</div>");
        }
        return sb.ToString();
    }

    // ── helpers ────────────────────────────────────────────────────────────────
    private static string Card(string title, string body)
        => "<div class=\"card\"><div class=\"card-hd\"><h3>"+title+"</h3></div><div class=\"card-bd\">"+body+"</div></div>";

    private static void Bar(StringBuilder sb, double pct, string color)
    {
        int w = Math.Min(100,(int)pct);
        sb.Append("<div class=\"bar-wrap\"><div class=\"bar-bg\"><div class=\"bar-fill\" style=\"width:")
          .Append(w).Append("%;background:").Append(color)
          .Append("\"></div></div><span style=\"font-size:11px;color:var(--text2)\">")
          .Append(pct.ToString("F1")).Append("%</span></div>");
    }

    private static string Fmt(int n)
    {
        if (n < 1000) return n.ToString();
        var s = n.ToString(); var b = new StringBuilder();
        for (int i=0;i<s.Length;i++) { if(i>0&&(s.Length-i)%3==0)b.Append(','); b.Append(s[i]); }
        return b.ToString();
    }
    private static string FB(long bytes) => bytes switch {
        >=1L<<30 => $"{(double)bytes/(1L<<30):F1} GB",
        >=1L<<20 => $"{(double)bytes/(1L<<20):F1} MB",
        >=1L<<10 => $"{(double)bytes/(1L<<10):F0} KB",
        _ => bytes+" B"
    };
    private static string HE(string s) =>
        s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace("\"","&quot;");
}
