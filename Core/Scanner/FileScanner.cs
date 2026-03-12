using System.Collections.Concurrent;
using LogAudit.Core.Detector;
using LogAudit.Core.Models;
using LogAudit.Core.Parser;

namespace LogAudit.Core.Scanner;

public class ScanResult
{
    public List<Hit>  Hits       { get; set; } = [];
    public long TotalLines { get; set; }
    public string FilePath { get; set; } = "";
    public long FileSize   { get; set; }
}

/// <summary>
/// Streams a file in chunks of <see cref="ChunkLines"/> lines.
/// Each chunk is parsed + rule-matched in parallel, then the caller's
/// <paramref name="onChunk"/> callback receives the entries (for analysis)
/// and any hits. The chunk is discarded before reading the next one,
/// so peak RAM usage is proportional to chunk size, not file size.
/// </summary>
public class FileScanner
{
    private readonly RuleEngine _engine;
    private readonly int        _workers;

    /// <summary>Lines per chunk. 50 000 ≈ 10-20 MB RAM working set.</summary>
    private const int ChunkLines = 50_000;

    public FileScanner(RuleEngine engine, int workers = 0)
    {
        _engine  = engine;
        _workers = workers <= 0 ? Math.Max(1, Environment.ProcessorCount - 1) : workers;
    }

    public async Task<ScanResult> ScanFileAsync(
        string path,
        Action<IReadOnlyList<LogEntry>, IReadOnlyList<Hit>>? onChunk = null,
        IProgress<(long bytesRead, long totalBytes, long linesProcessed)>? progress = null,
        CancellationToken ct = default)
    {
        var fi     = new FileInfo(path);
        var result = new ScanResult { FilePath = path, FileSize = fi.Exists ? fi.Length : 0 };
        long totalBytes = result.FileSize;

        await using var fs     = new FileStream(path, FileMode.Open, FileAccess.Read,
                                                FileShare.ReadWrite, bufferSize: 1 << 16);
        using  var      reader = new StreamReader(fs, detectEncodingFromByteOrderMarks: true);

        var chunkLines  = new List<string>(ChunkLines);
        var chunkNums   = new List<long>(ChunkLines);
        long globalLine = 0;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            // ── Read one chunk ────────────────────────────────────────────────
            chunkLines.Clear();
            chunkNums.Clear();

            string? line;
            while (chunkLines.Count < ChunkLines &&
                   (line = await reader.ReadLineAsync(ct)) != null)
            {
                globalLine++;
                if (!string.IsNullOrEmpty(line))
                {
                    chunkLines.Add(line);
                    chunkNums.Add(globalLine);
                }
            }

            if (chunkLines.Count == 0) break;

            // ── Parse + match in parallel (background thread) ─────────────────
            var entries    = new LogEntry[chunkLines.Count];
            var hitBag     = new ConcurrentBag<Hit>();
            var localLines = chunkLines.ToArray();   // capture before clearing
            var localNums  = chunkNums.ToArray();

            await Task.Run(() =>
            {
                Parallel.For(0, localLines.Length,
                    new ParallelOptions { MaxDegreeOfParallelism = _workers, CancellationToken = ct },
                    i =>
                    {
                        var e      = LogParser.Parse(localLines[i], (int)localNums[i]);
                        entries[i] = e;
                        var target = e.SearchTarget();
                        foreach (var rule in _engine.Rules)
                            if (rule.Match(target))
                                hitBag.Add(new Hit
                                {
                                    Rule    = rule,
                                    LineNum = (int)localNums[i],
                                    IP      = e.IP, Method = e.Method, URI = e.URI,
                                    UA      = e.UserAgent, Status = e.Status,
                                    Raw     = localLines[i], Time = e.Time
                                });
                    });
            }, ct);

            // ── Stream results to caller (analyze on-the-fly) ─────────────────
            var validEntries = entries.Where(e => e != null).ToList();
            var chunkHits    = hitBag.ToList();
            onChunk?.Invoke(validEntries, chunkHits);

            result.TotalLines += localLines.Length;
            foreach (var h in chunkHits) result.Hits.Add(h);

            progress?.Report((fs.Position, totalBytes, result.TotalLines));

            // Let GC collect this chunk before reading the next
            await Task.Yield();
        }

        return result;
    }
}


