using System.Text.RegularExpressions;
using LogAudit.Core.Models;

namespace LogAudit.Core.Parser;

public static class LogParser
{
    private static readonly Regex ReCombined = new(
        @"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+""(\S+)\s+(\S+)\s+(HTTP/\S+)""\s+(\d{3})\s+(\d+|-)\s+""([^""]*)""\s+""([^""]*)""",
        RegexOptions.Compiled);

    private static readonly Regex ReCommon = new(
        @"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+""(\S+)\s+(\S+)\s+(HTTP/\S+)""\s+(\d{3})\s+(\d+|-)",
        RegexOptions.Compiled);

    private const string TimeLayout = "dd/MMM/yyyy:HH:mm:ss zzz";

    public static LogEntry Parse(string raw, int lineNum)
    {
        var e = new LogEntry { Raw = raw, Line = lineNum };

        var m = ReCombined.Match(raw);
        if (m.Success)
        {
            Fill(e, m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value,
                m.Groups[4].Value, m.Groups[5].Value, m.Groups[6].Value,
                m.Groups[7].Value, m.Groups[8].Value, m.Groups[9].Value);
            return e;
        }

        m = ReCommon.Match(raw);
        if (m.Success)
        {
            Fill(e, m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value,
                m.Groups[4].Value, m.Groups[5].Value, m.Groups[6].Value,
                m.Groups[7].Value, "", "");
            return e;
        }

        return e;
    }

    private static void Fill(LogEntry e, string ip, string ts, string method,
        string uri, string proto, string status, string size, string referer, string ua)
    {
        e.Valid = true;
        e.IP = ip;
        e.Method = method.ToUpper();
        e.URI = uri;
        e.Protocol = proto;
        e.Referer = referer;
        e.UserAgent = ua;

        if (int.TryParse(status, out var s)) e.Status = s;
        if (size != "-" && long.TryParse(size, out var sz)) e.Size = sz;

        // Parse time
        try
        {
            // 02/Jan/2006:15:04:05 -0700
            if (DateTime.TryParseExact(ts, "dd/MMM/yyyy:HH:mm:ss zzz",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var dt))
                e.Time = dt;
        }
        catch { }

        // Parse path/query/extension
        var qIdx = uri.IndexOf('?');
        if (qIdx >= 0)
        {
            e.Path = uri[..qIdx];
            e.Query = uri[(qIdx + 1)..];
        }
        else
        {
            e.Path = uri;
        }

        var seg = e.Path;
        var slashIdx = seg.LastIndexOf('/');
        if (slashIdx >= 0) seg = seg[(slashIdx + 1)..];
        var dotIdx = seg.LastIndexOf('.');
        if (dotIdx >= 0) e.Extension = seg[(dotIdx + 1)..].ToLower();
    }
}
