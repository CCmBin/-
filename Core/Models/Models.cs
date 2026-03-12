namespace LogAudit.Core.Models;

public class LogEntry
{
    public string Raw { get; set; } = "";
    public string IP { get; set; } = "";
    public DateTime Time { get; set; }
    public string Method { get; set; } = "";
    public string URI { get; set; } = "";
    public string Path { get; set; } = "";
    public string Query { get; set; } = "";
    public string Extension { get; set; } = "";
    public string Protocol { get; set; } = "";
    public int Status { get; set; }
    public long Size { get; set; }
    public string Referer { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public int Line { get; set; }
    public bool Valid { get; set; }

    public bool IsStatic() => Extension is "js" or "css" or "png" or "jpg" or "jpeg"
        or "gif" or "ico" or "svg" or "woff" or "woff2" or "ttf" or "eot" or "otf"
        or "map" or "mp4" or "webm" or "mp3" or "ogg" or "wav" or "pdf" or "zip"
        or "gz" or "tar" or "rar" or "xml" or "txt" or "csv" or "json";

    public string SearchTarget() => Valid
        ? $"{Method} {URI} {UserAgent} {Referer}"
        : Raw;
}

public enum Severity { Low, Medium, High, Critical }

public static class SeverityHelper
{
    public static string Label(Severity s) => s switch
    {
        Severity.Critical => "严重",
        Severity.High => "高危",
        Severity.Medium => "中危",
        Severity.Low => "低危",
        _ => s.ToString()
    };

    public static string Color(Severity s) => s switch
    {
        Severity.Critical => "#ff2255",
        Severity.High => "#ff7700",
        Severity.Medium => "#ffbb00",
        Severity.Low => "#33bbff",
        _ => "#58a6ff"
    };

    public static int Rank(Severity s) => (int)s;
}

public class DetectionRule
{
    public string ID { get; set; } = "";
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public Severity Severity { get; set; }
    public List<System.Text.RegularExpressions.Regex> Patterns { get; set; } = [];

    public bool Match(string target)
    {
        foreach (var re in Patterns)
            if (re.IsMatch(target)) return true;
        return false;
    }
}

public class Hit
{
    public DetectionRule Rule { get; set; } = null!;
    public int LineNum { get; set; }
    public string IP { get; set; } = "";
    public string Method { get; set; } = "";
    public string URI { get; set; } = "";
    public string UA { get; set; } = "";
    public int Status { get; set; }
    public string Raw { get; set; } = "";
    public DateTime Time { get; set; }
}
