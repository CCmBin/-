using LogAudit.Core.Models;

namespace LogAudit.Core.Analyzer;

public record KV(string Key, int Value);

public class IPStat
{
    public string IP { get; set; } = "";
    public int Requests { get; set; }
    public long Bytes { get; set; }
    public string BytesStr { get; set; } = "";
    public double AvgSize { get; set; }
    public int Status4xx { get; set; }
    public int Status5xx { get; set; }
    public string FirstSeen { get; set; } = "";
    public string LastSeen { get; set; } = "";
    public List<string> TopPaths { get; set; } = [];
    public string AbuseScore { get; set; } = "";
}

public class PageStat
{
    public string Path { get; set; } = "";
    public int Requests { get; set; }
    public long Bytes { get; set; }
    public string BytesStr { get; set; } = "";
    public string AvgSize { get; set; } = "";
    public double ErrorRate { get; set; }
    public int UniqueIPs { get; set; }
}

public class DeadLink
{
    public string Path { get; set; } = "";
    public int Count { get; set; }
    public List<string> Referers { get; set; } = [];
}

public class StatusStat
{
    public int Code { get; set; }
    public int Count { get; set; }
    public double Pct { get; set; }
    public string Desc { get; set; } = "";
    public string Color { get; set; } = "";
}

public class TimeStat
{
    public string T { get; set; } = "";
    public int C { get; set; }
}

public class SlowRequest
{
    public string Path { get; set; } = "";
    public long AvgSize { get; set; }
    public string AvgSizeStr { get; set; } = "";
    public int Count { get; set; }
}

public class AnalysisResult
{
    // Basic stats
    public int TotalLines { get; set; }
    public int ValidLines { get; set; }
    public int InvalidLines { get; set; }
    public int TotalRequests { get; set; }
    public long TotalBytes { get; set; }
    public string TotalBytesStr { get; set; } = "";
    public int TotalIPs { get; set; }
    public string DateRange { get; set; } = "";
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public TimeSpan Duration { get; set; }

    // Status codes
    public int Status2xx { get; set; }
    public int Status3xx { get; set; }
    public int Status4xx { get; set; }
    public int Status5xx { get; set; }
    public int Status404 { get; set; }
    public int Status500 { get; set; }
    public double ErrorRate { get; set; }
    public double SuccessRate { get; set; }
    public List<StatusStat> StatusStats { get; set; } = [];

    // Traffic patterns
    public double AvgPerHour { get; set; }
    public double AvgPerDay { get; set; }
    public string PeakHour { get; set; } = "";
    public int PeakHourCount { get; set; }
    public string PeakDay { get; set; } = "";
    public int PeakDayCount { get; set; }
    public double PeakToPeakRatio { get; set; }

    // Top lists
    public List<IPStat> TopIPs { get; set; } = [];
    public List<PageStat> TopPages { get; set; } = [];
    public List<PageStat> TopStatic { get; set; } = [];
    public List<DeadLink> DeadLinks { get; set; } = [];
    public List<KV> TopReferers { get; set; } = [];
    public List<KV> MethodStats { get; set; } = [];
    public List<KV> ProtoStats { get; set; } = [];
    public List<KV> BrowserStats { get; set; } = [];
    public List<KV> OSStats { get; set; } = [];
    public List<KV> ExtStats { get; set; } = [];
    public List<KV> CountryStats { get; set; } = [];

    // Time series
    public List<TimeStat> HourlyStats { get; set; } = [];
    public List<TimeStat> DailyStats { get; set; } = [];

    // New enhanced metrics
    public List<SlowRequest> LargestRequests { get; set; } = [];
    public List<KV> HourOfDayStats { get; set; } = [];   // 0-23 aggregated
    public List<KV> DayOfWeekStats { get; set; } = [];   // Mon-Sun
    public int UniquePaths { get; set; }
    public int BotRequests { get; set; }
    public double BotRate { get; set; }
    public int MobileRequests { get; set; }
    public double MobileRate { get; set; }
    public string AvgRequestSize { get; set; } = "";
    public List<KV> TopQueryParams { get; set; } = [];
}

public static class LogAnalyzer
{
    public static AnalysisResult Analyze(IEnumerable<LogEntry> entries)
    {
        var r = new AnalysisResult();
        bool any = false;

        var ipReq = new Dictionary<string, int>();
        var ipBytes = new Dictionary<string, long>();
        var ipFirst = new Dictionary<string, DateTime>();
        var ipLast = new Dictionary<string, DateTime>();
        var ip4xx = new Dictionary<string, int>();
        var ip5xx = new Dictionary<string, int>();
        var ipPaths = new Dictionary<string, Dictionary<string, int>>();

        var pageReq = new Dictionary<string, int>();
        var pageBytes = new Dictionary<string, long>();
        var pageErrors = new Dictionary<string, int>();
        var pageIPs = new Dictionary<string, HashSet<string>>();

        var staticReq = new Dictionary<string, int>();
        var staticBytes = new Dictionary<string, long>();

        var statusMap = new Dictionary<int, int>();
        var hourMap = new Dictionary<string, int>();
        var dayMap = new Dictionary<string, int>();
        var hourOfDayMap = new Dictionary<int, int>();
        var dowMap = new Dictionary<int, int>();
        var methodMap = new Dictionary<string, int>();
        var protoMap = new Dictionary<string, int>();
        var browserMap = new Dictionary<string, int>();
        var osMap = new Dictionary<string, int>();
        var refMap = new Dictionary<string, int>();
        var extMap = new Dictionary<string, int>();
        var deadMap = new Dictionary<string, int>();
        var deadRefMap = new Dictionary<string, HashSet<string>>();
        var ipSet = new HashSet<string>();
        var pathSet = new HashSet<string>();
        var queryParams = new Dictionary<string, int>();

        DateTime first = DateTime.MaxValue, last = DateTime.MinValue;
        long totalSize = 0;

        foreach (var e in entries)
        {
            any = true;
            if (!e.Valid) { r.InvalidLines++; continue; }
            r.ValidLines++;
            r.TotalRequests++;
            totalSize += e.Size;
            ipSet.Add(e.IP);
            pathSet.Add(e.Path);

            // IP stats
            ipReq.TryAdd(e.IP, 0); ipReq[e.IP]++;
            ipBytes.TryAdd(e.IP, 0); ipBytes[e.IP] += e.Size;
            if (!ipFirst.ContainsKey(e.IP) || e.Time < ipFirst[e.IP]) ipFirst[e.IP] = e.Time;
            if (!ipLast.ContainsKey(e.IP) || e.Time > ipLast[e.IP]) ipLast[e.IP] = e.Time;

            // Status
            statusMap.TryAdd(e.Status, 0); statusMap[e.Status]++;
            switch (e.Status)
            {
                case >= 200 and < 300: r.Status2xx++; break;
                case >= 300 and < 400: r.Status3xx++; break;
                case >= 400 and < 500:
                    r.Status4xx++;
                    if (e.Status == 404)
                    {
                        r.Status404++;
                        deadMap.TryAdd(e.Path, 0); deadMap[e.Path]++;
                        if (!deadRefMap.ContainsKey(e.Path)) deadRefMap[e.Path] = [];
                        if (!string.IsNullOrEmpty(e.Referer) && e.Referer != "-")
                            deadRefMap[e.Path].Add(e.Referer);
                    }
                    ip4xx.TryAdd(e.IP, 0); ip4xx[e.IP]++;
                    pageErrors.TryAdd(e.Path, 0); pageErrors[e.Path]++;
                    break;
                case >= 500:
                    r.Status5xx++;
                    if (e.Status == 500) r.Status500++;
                    ip5xx.TryAdd(e.IP, 0); ip5xx[e.IP]++;
                    break;
            }

            // Pages
            if (e.IsStatic())
            {
                staticReq.TryAdd(e.Path, 0); staticReq[e.Path]++;
                staticBytes.TryAdd(e.Path, 0); staticBytes[e.Path] += e.Size;
            }
            else if (!string.IsNullOrEmpty(e.Path))
            {
                pageReq.TryAdd(e.Path, 0); pageReq[e.Path]++;
                pageBytes.TryAdd(e.Path, 0); pageBytes[e.Path] += e.Size;
                if (!pageIPs.ContainsKey(e.Path)) pageIPs[e.Path] = [];
                pageIPs[e.Path].Add(e.IP);
            }

            // Methods, protocols
            if (!string.IsNullOrEmpty(e.Method)) { methodMap.TryAdd(e.Method, 0); methodMap[e.Method]++; }
            if (!string.IsNullOrEmpty(e.Protocol)) { protoMap.TryAdd(e.Protocol, 0); protoMap[e.Protocol]++; }
            if (!string.IsNullOrEmpty(e.Extension)) { extMap.TryAdd(e.Extension, 0); extMap[e.Extension]++; }

            // UA parsing
            if (!string.IsNullOrEmpty(e.UserAgent) && e.UserAgent != "-")
            {
                var (browser, os, isBot, isMobile) = ParseUA(e.UserAgent);
                browserMap.TryAdd(browser, 0); browserMap[browser]++;
                osMap.TryAdd(os, 0); osMap[os]++;
                if (isBot) r.BotRequests++;
                if (isMobile) r.MobileRequests++;
            }

            // Referers
            if (!string.IsNullOrEmpty(e.Referer) && e.Referer != "-")
            {
                var domain = RefDomain(e.Referer);
                if (!string.IsNullOrEmpty(domain)) { refMap.TryAdd(domain, 0); refMap[domain]++; }
            }

            // Time series
            if (e.Time != default)
            {
                if (e.Time < first) first = e.Time;
                if (e.Time > last) last = e.Time;

                var hKey = e.Time.ToString("MM-dd HH:00");
                hourMap.TryAdd(hKey, 0); hourMap[hKey]++;

                var dKey = e.Time.ToString("yyyy-MM-dd");
                dayMap.TryAdd(dKey, 0); dayMap[dKey]++;

                hourOfDayMap.TryAdd(e.Time.Hour, 0); hourOfDayMap[e.Time.Hour]++;
                dowMap.TryAdd((int)e.Time.DayOfWeek, 0); dowMap[(int)e.Time.DayOfWeek]++;
            }

            // Query params
            if (!string.IsNullOrEmpty(e.Query))
            {
                foreach (var part in e.Query.Split('&'))
                {
                    var eq = part.IndexOf('=');
                    var key = eq >= 0 ? part[..eq] : part;
                    if (!string.IsNullOrEmpty(key) && key.Length < 50)
                    { queryParams.TryAdd(key, 0); queryParams[key]++; }
                }
            }

            // IP paths tracking (top 5 per IP)
            if (!ipPaths.ContainsKey(e.IP)) ipPaths[e.IP] = [];
            if (ipPaths[e.IP].Count < 100)
            { ipPaths[e.IP].TryAdd(e.Path, 0); ipPaths[e.IP][e.Path]++; }
        }

        // ── Fill result ───────────────────────────────────────────────────────
        if (!any) return r;
        r.TotalLines = r.ValidLines + r.InvalidLines;
        r.TotalBytes = totalSize;
        r.TotalBytesStr = BytesFmt(totalSize);
        r.TotalIPs = ipSet.Count;
        r.UniquePaths = pathSet.Count;
        r.AvgRequestSize = BytesFmt(r.TotalRequests > 0 ? totalSize / r.TotalRequests : 0);

        if (first != DateTime.MaxValue)
        {
            r.StartTime = first;
            r.EndTime = last;
            r.Duration = last - first;
            r.DateRange = $"{first:yyyy-MM-dd} 至 {last:yyyy-MM-dd}";
        }

        if (r.TotalRequests > 0)
        {
            r.ErrorRate = (double)(r.Status4xx + r.Status5xx) / r.TotalRequests * 100;
            r.SuccessRate = (double)r.Status2xx / r.TotalRequests * 100;
            r.BotRate = (double)r.BotRequests / r.TotalRequests * 100;
            r.MobileRate = (double)r.MobileRequests / r.TotalRequests * 100;
        }

        // Status stats
        foreach (var (code, cnt) in statusMap)
        {
            r.StatusStats.Add(new StatusStat
            {
                Code = code, Count = cnt,
                Pct = r.TotalRequests > 0 ? (double)cnt / r.TotalRequests * 100 : 0,
                Desc = StatusDesc(code), Color = StatusColor(code)
            });
        }
        r.StatusStats.Sort((a, b) => b.Count - a.Count);

        // Top IPs
        foreach (var kv in TopN(ipReq, 20))
        {
            var ipStat = new IPStat
            {
                IP = kv.Key,
                Requests = kv.Value,
                Bytes = ipBytes.GetValueOrDefault(kv.Key),
                Status4xx = ip4xx.GetValueOrDefault(kv.Key),
                Status5xx = ip5xx.GetValueOrDefault(kv.Key),
            };
            ipStat.BytesStr = BytesFmt(ipStat.Bytes);
            ipStat.AvgSize = ipStat.Requests > 0 ? ipStat.Bytes / ipStat.Requests : 0;

            if (ipFirst.TryGetValue(kv.Key, out var f) && f != default)
                ipStat.FirstSeen = f.ToString("MM-dd HH:mm");
            if (ipLast.TryGetValue(kv.Key, out var l) && l != default)
                ipStat.LastSeen = l.ToString("MM-dd HH:mm");

            // Abuse score
            double errorRatio = ipStat.Requests > 0
                ? (double)(ipStat.Status4xx + ipStat.Status5xx) / ipStat.Requests
                : 0;
            ipStat.AbuseScore = errorRatio > 0.5 ? "⚠ 高" : errorRatio > 0.2 ? "中" : "低";

            // Top paths for this IP
            if (ipPaths.TryGetValue(kv.Key, out var pp))
                ipStat.TopPaths = TopN(pp, 3).Select(x => x.Key).ToList();

            r.TopIPs.Add(ipStat);
        }

        // Top pages
        foreach (var kv in TopN(pageReq, 15))
        {
            var avg = kv.Value > 0 ? pageBytes.GetValueOrDefault(kv.Key) / kv.Value : 0;
            var errCount = pageErrors.GetValueOrDefault(kv.Key);
            r.TopPages.Add(new PageStat
            {
                Path = kv.Key, Requests = kv.Value,
                Bytes = pageBytes.GetValueOrDefault(kv.Key),
                BytesStr = BytesFmt(pageBytes.GetValueOrDefault(kv.Key)),
                AvgSize = BytesFmt(avg),
                ErrorRate = kv.Value > 0 ? (double)errCount / kv.Value * 100 : 0,
                UniqueIPs = pageIPs.TryGetValue(kv.Key, out var ips2) ? ips2.Count : 0
            });
        }

        // Top static
        foreach (var kv in TopN(staticReq, 10))
        {
            var avg = kv.Value > 0 ? staticBytes.GetValueOrDefault(kv.Key) / kv.Value : 0;
            r.TopStatic.Add(new PageStat
            {
                Path = kv.Key, Requests = kv.Value,
                Bytes = staticBytes.GetValueOrDefault(kv.Key),
                BytesStr = BytesFmt(staticBytes.GetValueOrDefault(kv.Key)),
                AvgSize = BytesFmt(avg)
            });
        }

        // Dead links
        foreach (var kv in TopN(deadMap, 20))
        {
            var refs = deadRefMap.TryGetValue(kv.Key, out var rs)
                ? rs.Take(3).ToList() : [];
            r.DeadLinks.Add(new DeadLink { Path = kv.Key, Count = kv.Value, Referers = refs });
        }

        // Time series
        var hkeys = hourMap.Keys.OrderBy(k => k).ToList();
        string peakH = "", peakD = "";
        int peakHC = 0, peakDC = 0;
        foreach (var k in hkeys)
        {
            var c = hourMap[k];
            r.HourlyStats.Add(new TimeStat { T = k, C = c });
            if (c > peakHC) { peakHC = c; peakH = k; }
        }
        r.PeakHour = peakH; r.PeakHourCount = peakHC;
        if (r.HourlyStats.Count > 0)
            r.AvgPerHour = (double)r.TotalRequests / r.HourlyStats.Count;

        foreach (var k in dayMap.Keys.OrderBy(k => k))
        {
            var c = dayMap[k];
            r.DailyStats.Add(new TimeStat { T = k, C = c });
            if (c > peakDC) { peakDC = c; peakD = k; }
        }
        r.PeakDay = peakD; r.PeakDayCount = peakDC;
        if (r.DailyStats.Count > 0)
            r.AvgPerDay = (double)r.TotalRequests / r.DailyStats.Count;

        // Hour of day (0-23)
        for (int h = 0; h < 24; h++)
            r.HourOfDayStats.Add(new KV($"{h:D2}:00", hourOfDayMap.GetValueOrDefault(h)));

        // Day of week
        var dowNames = new[] { "周日", "周一", "周二", "周三", "周四", "周五", "周六" };
        for (int d = 0; d < 7; d++)
            r.DayOfWeekStats.Add(new KV(dowNames[d], dowMap.GetValueOrDefault(d)));

        r.MethodStats = TopN(methodMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.ProtoStats = TopN(protoMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.BrowserStats = TopN(browserMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.OSStats = TopN(osMap, 8).Select(x => new KV(x.Key, x.Value)).ToList();
        r.TopReferers = TopN(refMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.ExtStats = TopN(extMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.TopQueryParams = TopN(queryParams, 10).Select(x => new KV(x.Key, x.Value)).ToList();

        // Largest pages by avg size
        r.LargestRequests = pageReq
            .Where(kv => kv.Value >= 5)
            .Select(kv => new SlowRequest
            {
                Path = kv.Key,
                AvgSize = pageBytes.GetValueOrDefault(kv.Key) / kv.Value,
                AvgSizeStr = BytesFmt(pageBytes.GetValueOrDefault(kv.Key) / kv.Value),
                Count = kv.Value
            })
            .OrderByDescending(x => x.AvgSize)
            .Take(10)
            .ToList();

        return r;
    }

    private static List<KeyValuePair<string, int>> TopN(Dictionary<string, int> m, int n)
        => m.OrderByDescending(x => x.Value).Take(n).ToList();

    public static string BytesFmt(long b) => b switch
    {
        >= 1L << 30 => $"{(double)b / (1L << 30):F2} GB",
        >= 1L << 20 => $"{(double)b / (1L << 20):F2} MB",
        >= 1L << 10 => $"{(double)b / (1L << 10):F1} KB",
        _ => $"{b} B"
    };

    private static (string browser, string os, bool isBot, bool isMobile) ParseUA(string ua)
    {
        var l = ua.ToLower();
        string browser = l switch
        {
            _ when l.Contains("edg/") || l.Contains("edge/") => "Edge",
            _ when l.Contains("chrome") && !l.Contains("chromium") => "Chrome",
            _ when l.Contains("firefox") => "Firefox",
            _ when l.Contains("safari") && !l.Contains("chrome") => "Safari",
            _ when l.Contains("msie") || l.Contains("trident") => "IE",
            _ when l.Contains("curl") => "curl",
            _ when l.Contains("python") => "Python",
            _ when l.Contains("go-http") => "Go HTTP",
            _ when l.Contains("wget") => "wget",
            _ when l.Contains("bot") || l.Contains("spider") || l.Contains("crawl") => "Bot/Spider",
            _ => "其他"
        };
        string os = l switch
        {
            _ when l.Contains("windows") => "Windows",
            _ when l.Contains("android") => "Android",
            _ when l.Contains("iphone") || l.Contains("ipad") => "iOS",
            _ when l.Contains("mac os") || l.Contains("macos") => "macOS",
            _ when l.Contains("linux") => "Linux",
            _ => "其他"
        };
        bool isBot = l.Contains("bot") || l.Contains("spider") || l.Contains("crawl")
            || l.Contains("sqlmap") || l.Contains("nmap") || l.Contains("nikto")
            || l.Contains("nuclei") || l.Contains("burp") || l.Contains("masscan");
        bool isMobile = l.Contains("android") || l.Contains("iphone") || l.Contains("ipad")
            || l.Contains("mobile");
        return (browser, os, isBot, isMobile);
    }

    private static string RefDomain(string ref_)
    {
        var s = ref_.TrimStart();
        if (s.StartsWith("https://")) s = s[8..];
        else if (s.StartsWith("http://")) s = s[7..];
        var idx = s.IndexOf('/');
        return idx >= 0 ? s[..idx] : s;
    }

    private static string StatusDesc(int code) => code switch
    {
        200 => "OK", 201 => "Created", 204 => "No Content", 206 => "Partial Content",
        301 => "Moved Permanently", 302 => "Found", 304 => "Not Modified",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 405 => "Method Not Allowed", 408 => "Request Timeout",
        413 => "Payload Too Large", 429 => "Too Many Requests",
        500 => "Internal Server Error", 502 => "Bad Gateway",
        503 => "Service Unavailable", 504 => "Gateway Timeout",
        _ => ""
    };

    private static string StatusColor(int code) => code switch
    {
        >= 200 and < 300 => "#3fb950",
        >= 300 and < 400 => "#58a6ff",
        >= 400 and < 500 => "#d29922",
        >= 500 => "#f85149",
        _ => "#8b949e"
    };
}
