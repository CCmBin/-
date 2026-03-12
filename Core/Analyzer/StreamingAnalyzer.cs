using LogAudit.Core.Models;

namespace LogAudit.Core.Analyzer;

/// <summary>
/// Incremental version of LogAnalyzer: call Feed() for each chunk of entries
/// (without storing them), then call BuildResult() once to get the final report.
/// Memory usage is O(unique IPs + unique paths), not O(total lines).
/// </summary>
public class StreamingAnalyzer
{
    // counters mirrored from LogAnalyzer
    private int  _validLines, _invalidLines, _totalRequests;
    private int  _s2xx, _s3xx, _s4xx, _s5xx, _s404, _s500;
    private int  _botReqs, _mobileReqs;
    private long _totalSize;
    private DateTime _first = DateTime.MaxValue, _last = DateTime.MinValue;

    private readonly Dictionary<string, int>                    _ipReq      = [];
    private readonly Dictionary<string, long>                   _ipBytes    = [];
    private readonly Dictionary<string, DateTime>               _ipFirst    = [];
    private readonly Dictionary<string, DateTime>               _ipLast     = [];
    private readonly Dictionary<string, int>                    _ip4xx      = [];
    private readonly Dictionary<string, int>                    _ip5xx      = [];
    private readonly Dictionary<string, Dictionary<string,int>> _ipPaths    = [];
    private readonly Dictionary<string, int>                    _pageReq    = [];
    private readonly Dictionary<string, long>                   _pageBytes  = [];
    private readonly Dictionary<string, int>                    _pageErrors = [];
    private readonly Dictionary<string, HashSet<string>>        _pageIPs    = [];
    private readonly Dictionary<string, int>                    _staticReq  = [];
    private readonly Dictionary<string, long>                   _staticBytes= [];
    private readonly Dictionary<int,    int>                    _statusMap  = [];
    private readonly Dictionary<string, int>                    _hourMap    = [];
    private readonly Dictionary<string, int>                    _dayMap     = [];
    private readonly Dictionary<int,    int>                    _hourOfDay  = [];
    private readonly Dictionary<int,    int>                    _dowMap     = [];
    private readonly Dictionary<string, int>                    _methodMap  = [];
    private readonly Dictionary<string, int>                    _protoMap   = [];
    private readonly Dictionary<string, int>                    _browserMap = [];
    private readonly Dictionary<string, int>                    _osMap      = [];
    private readonly Dictionary<string, int>                    _refMap     = [];
    private readonly Dictionary<string, int>                    _extMap     = [];
    private readonly Dictionary<string, int>                    _deadMap    = [];
    private readonly Dictionary<string, HashSet<string>>        _deadRefMap = [];
    private readonly HashSet<string>                            _ipSet      = [];
    private readonly HashSet<string>                            _pathSet    = [];
    private readonly Dictionary<string, int>                    _queryParams= [];

    /// <summary>Feed one chunk of entries. Entries can be discarded by caller after this returns.</summary>
    public void Feed(IReadOnlyList<LogEntry> entries)
    {
        foreach (var e in entries)
        {
            if (!e.Valid) { _invalidLines++; continue; }
            _validLines++;
            _totalRequests++;
            _totalSize += e.Size;
            _ipSet.Add(e.IP);
            _pathSet.Add(e.Path);

            Inc(_ipReq, e.IP);
            Add(_ipBytes, e.IP, e.Size);
            if (!_ipFirst.TryGetValue(e.IP, out var f) || e.Time < f) _ipFirst[e.IP] = e.Time;
            if (!_ipLast.TryGetValue(e.IP, out var l) || e.Time > l)  _ipLast[e.IP]  = e.Time;

            Inc(_statusMap, e.Status);
            switch (e.Status)
            {
                case >= 200 and < 300: _s2xx++; break;
                case >= 300 and < 400: _s3xx++; break;
                case >= 400 and < 500:
                    _s4xx++;
                    if (e.Status == 404)
                    {
                        _s404++;
                        Inc(_deadMap, e.Path);
                        if (!_deadRefMap.ContainsKey(e.Path)) _deadRefMap[e.Path] = [];
                        if (!string.IsNullOrEmpty(e.Referer) && e.Referer != "-")
                            _deadRefMap[e.Path].Add(e.Referer);
                    }
                    Inc(_ip4xx, e.IP);
                    Inc(_pageErrors, e.Path);
                    break;
                case >= 500:
                    _s5xx++;
                    if (e.Status == 500) _s500++;
                    Inc(_ip5xx, e.IP);
                    break;
            }

            if (e.IsStatic())
            {
                Inc(_staticReq, e.Path);
                Add(_staticBytes, e.Path, e.Size);
            }
            else if (!string.IsNullOrEmpty(e.Path))
            {
                Inc(_pageReq, e.Path);
                Add(_pageBytes, e.Path, e.Size);
                if (!_pageIPs.ContainsKey(e.Path)) _pageIPs[e.Path] = [];
                _pageIPs[e.Path].Add(e.IP);
            }

            if (!string.IsNullOrEmpty(e.Method))    Inc(_methodMap, e.Method);
            if (!string.IsNullOrEmpty(e.Protocol))  Inc(_protoMap, e.Protocol);
            if (!string.IsNullOrEmpty(e.Extension)) Inc(_extMap, e.Extension);

            if (!string.IsNullOrEmpty(e.UserAgent) && e.UserAgent != "-")
            {
                var (browser, os, isBot, isMobile) = ParseUA(e.UserAgent);
                Inc(_browserMap, browser);
                Inc(_osMap, os);
                if (isBot)    _botReqs++;
                if (isMobile) _mobileReqs++;
            }

            if (!string.IsNullOrEmpty(e.Referer) && e.Referer != "-")
            {
                var domain = RefDomain(e.Referer);
                if (!string.IsNullOrEmpty(domain)) Inc(_refMap, domain);
            }

            if (e.Time != default)
            {
                if (e.Time < _first) _first = e.Time;
                if (e.Time > _last)  _last  = e.Time;
                Inc(_hourMap, e.Time.ToString("MM-dd HH:00"));
                Inc(_dayMap,  e.Time.ToString("yyyy-MM-dd"));
                Inc(_hourOfDay, e.Time.Hour);
                Inc(_dowMap, (int)e.Time.DayOfWeek);
            }

            if (!string.IsNullOrEmpty(e.Query))
            {
                foreach (var part in e.Query.Split('&'))
                {
                    var eq  = part.IndexOf('=');
                    var key = eq >= 0 ? part[..eq] : part;
                    if (!string.IsNullOrEmpty(key) && key.Length < 50) Inc(_queryParams, key);
                }
            }

            if (!_ipPaths.ContainsKey(e.IP)) _ipPaths[e.IP] = [];
            if (_ipPaths[e.IP].Count < 100) Inc(_ipPaths[e.IP], e.Path);
        }
    }

    public AnalysisResult BuildResult()
    {
        var r = new AnalysisResult
        {
            TotalLines    = _validLines + _invalidLines,
            ValidLines    = _validLines,
            InvalidLines  = _invalidLines,
            TotalRequests = _totalRequests,
            TotalBytes    = _totalSize,
            TotalBytesStr = LogAnalyzer.BytesFmt(_totalSize),
            TotalIPs      = _ipSet.Count,
            UniquePaths   = _pathSet.Count,
            AvgRequestSize= LogAnalyzer.BytesFmt(_totalRequests > 0 ? _totalSize / _totalRequests : 0),
            Status2xx = _s2xx, Status3xx = _s3xx,
            Status4xx = _s4xx, Status5xx = _s5xx,
            Status404 = _s404, Status500 = _s500,
            BotRequests    = _botReqs,
            MobileRequests = _mobileReqs,
        };

        if (_first != DateTime.MaxValue)
        {
            r.StartTime = _first; r.EndTime = _last;
            r.Duration  = _last - _first;
            r.DateRange = $"{_first:yyyy-MM-dd} 至 {_last:yyyy-MM-dd}";
        }

        if (_totalRequests > 0)
        {
            r.ErrorRate   = (double)(_s4xx + _s5xx) / _totalRequests * 100;
            r.SuccessRate = (double)_s2xx            / _totalRequests * 100;
            r.BotRate     = (double)_botReqs         / _totalRequests * 100;
            r.MobileRate  = (double)_mobileReqs      / _totalRequests * 100;
        }

        foreach (var (code, cnt) in _statusMap)
            r.StatusStats.Add(new StatusStat
            {
                Code = code, Count = cnt,
                Pct  = _totalRequests > 0 ? (double)cnt / _totalRequests * 100 : 0,
                Desc = StatusDesc(code), Color = StatusColor(code)
            });
        r.StatusStats.Sort((a, b) => b.Count - a.Count);

        foreach (var kv in TopN(_ipReq, 20))
        {
            var ipStat = new IPStat
            {
                IP        = kv.Key,
                Requests  = kv.Value,
                Bytes     = _ipBytes.GetValueOrDefault(kv.Key),
                Status4xx = _ip4xx.GetValueOrDefault(kv.Key),
                Status5xx = _ip5xx.GetValueOrDefault(kv.Key),
            };
            ipStat.BytesStr = LogAnalyzer.BytesFmt(ipStat.Bytes);
            ipStat.AvgSize  = ipStat.Requests > 0 ? ipStat.Bytes / ipStat.Requests : 0;
            if (_ipFirst.TryGetValue(kv.Key, out var fi) && fi != default)
                ipStat.FirstSeen = fi.ToString("MM-dd HH:mm");
            if (_ipLast.TryGetValue(kv.Key, out var li) && li != default)
                ipStat.LastSeen = li.ToString("MM-dd HH:mm");
            double er = ipStat.Requests > 0
                ? (double)(ipStat.Status4xx + ipStat.Status5xx) / ipStat.Requests : 0;
            ipStat.AbuseScore = er > 0.5 ? "⚠ 高" : er > 0.2 ? "中" : "低";
            if (_ipPaths.TryGetValue(kv.Key, out var pp))
                ipStat.TopPaths = TopN(pp, 3).Select(x => x.Key).ToList();
            r.TopIPs.Add(ipStat);
        }

        foreach (var kv in TopN(_pageReq, 15))
        {
            var avg = kv.Value > 0 ? _pageBytes.GetValueOrDefault(kv.Key) / kv.Value : 0;
            var err = _pageErrors.GetValueOrDefault(kv.Key);
            r.TopPages.Add(new PageStat
            {
                Path      = kv.Key, Requests = kv.Value,
                Bytes     = _pageBytes.GetValueOrDefault(kv.Key),
                BytesStr  = LogAnalyzer.BytesFmt(_pageBytes.GetValueOrDefault(kv.Key)),
                AvgSize   = LogAnalyzer.BytesFmt(avg),
                ErrorRate = kv.Value > 0 ? (double)err / kv.Value * 100 : 0,
                UniqueIPs = _pageIPs.TryGetValue(kv.Key, out var ips) ? ips.Count : 0
            });
        }

        foreach (var kv in TopN(_staticReq, 10))
        {
            var avg = kv.Value > 0 ? _staticBytes.GetValueOrDefault(kv.Key) / kv.Value : 0;
            r.TopStatic.Add(new PageStat
            {
                Path = kv.Key, Requests = kv.Value,
                Bytes = _staticBytes.GetValueOrDefault(kv.Key),
                BytesStr = LogAnalyzer.BytesFmt(_staticBytes.GetValueOrDefault(kv.Key)),
                AvgSize  = LogAnalyzer.BytesFmt(avg)
            });
        }

        foreach (var kv in TopN(_deadMap, 20))
        {
            var refs = _deadRefMap.TryGetValue(kv.Key, out var rs) ? rs.Take(3).ToList() : [];
            r.DeadLinks.Add(new DeadLink { Path = kv.Key, Count = kv.Value, Referers = refs });
        }

        string peakH = "", peakD = "";
        int peakHC = 0, peakDC = 0;
        foreach (var k in _hourMap.Keys.OrderBy(x => x))
        {
            var c = _hourMap[k];
            r.HourlyStats.Add(new TimeStat { T = k, C = c });
            if (c > peakHC) { peakHC = c; peakH = k; }
        }
        r.PeakHour = peakH; r.PeakHourCount = peakHC;
        if (r.HourlyStats.Count > 0) r.AvgPerHour = (double)_totalRequests / r.HourlyStats.Count;

        foreach (var k in _dayMap.Keys.OrderBy(x => x))
        {
            var c = _dayMap[k];
            r.DailyStats.Add(new TimeStat { T = k, C = c });
            if (c > peakDC) { peakDC = c; peakD = k; }
        }
        r.PeakDay = peakD; r.PeakDayCount = peakDC;
        if (r.DailyStats.Count > 0) r.AvgPerDay = (double)_totalRequests / r.DailyStats.Count;

        for (int h = 0; h < 24; h++)
            r.HourOfDayStats.Add(new KV($"{h:D2}:00", _hourOfDay.GetValueOrDefault(h)));
        var dowNames = new[] { "周日", "周一", "周二", "周三", "周四", "周五", "周六" };
        for (int d = 0; d < 7; d++)
            r.DayOfWeekStats.Add(new KV(dowNames[d], _dowMap.GetValueOrDefault(d)));

        r.MethodStats   = TopN(_methodMap,  10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.ProtoStats    = TopN(_protoMap,   10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.BrowserStats  = TopN(_browserMap, 10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.OSStats       = TopN(_osMap,       8).Select(x => new KV(x.Key, x.Value)).ToList();
        r.TopReferers   = TopN(_refMap,     10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.ExtStats      = TopN(_extMap,     10).Select(x => new KV(x.Key, x.Value)).ToList();
        r.TopQueryParams= TopN(_queryParams,10).Select(x => new KV(x.Key, x.Value)).ToList();

        r.LargestRequests = _pageReq
            .Where(kv => kv.Value >= 5)
            .Select(kv => new SlowRequest
            {
                Path = kv.Key,
                AvgSize    = _pageBytes.GetValueOrDefault(kv.Key) / kv.Value,
                AvgSizeStr = LogAnalyzer.BytesFmt(_pageBytes.GetValueOrDefault(kv.Key) / kv.Value),
                Count      = kv.Value
            })
            .OrderByDescending(x => x.AvgSize).Take(10).ToList();

        return r;
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    private static void Inc<T>(Dictionary<T, int> d, T k) where T : notnull
        { d.TryAdd(k, 0); d[k]++; }
    private static void Add<T>(Dictionary<T, long> d, T k, long v) where T : notnull
        { d.TryAdd(k, 0); d[k] += v; }
    private static List<KeyValuePair<TK, TV>> TopN<TK, TV>(
        Dictionary<TK, TV> m, int n) where TK : notnull where TV : IComparable<TV>
        => m.OrderByDescending(x => x.Value).Take(n).ToList();

    private static (string browser, string os, bool isBot, bool isMobile) ParseUA(string ua)
    {
        var l = ua.ToLowerInvariant();
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
        bool isBot    = l.Contains("bot") || l.Contains("spider") || l.Contains("crawl")
                     || l.Contains("sqlmap") || l.Contains("nmap") || l.Contains("nikto")
                     || l.Contains("nuclei") || l.Contains("burp") || l.Contains("masscan");
        bool isMobile = l.Contains("android") || l.Contains("iphone") || l.Contains("ipad")
                     || l.Contains("mobile");
        return (browser, os, isBot, isMobile);
    }

    private static string RefDomain(string r)
    {
        var s = r.TrimStart();
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
