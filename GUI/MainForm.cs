using System.Collections.Concurrent;
using System.Diagnostics;
using System.Drawing.Drawing2D;
using LogAudit.Core.Analyzer;
using LogAudit.Core.Detector;
using LogAudit.Core.Models;
using LogAudit.Core.Reporter;
using LogAudit.Core.Scanner;

namespace LogAudit.GUI;

public class MainForm : Form
{
    // ── State ─────────────────────────────────────────────────────────────────
    private readonly List<string> _files = [];
    private string _rulesPath = "";
    private string _outDir    = "";
    private CancellationTokenSource? _cts;

    // ── Batched log queue ─────────────────────────────────────────────────────
    private readonly ConcurrentQueue<(string text, Color color)> _logQueue = new();
    private System.Windows.Forms.Timer _logTimer = null!;

    // ── Controls ─────────────────────────────────────────────────────────────
    private ListView    _fileList      = null!;
    private RichTextBox _log           = null!;
    private ModernProgressBar _progress = null!;
    private Label       _progressLabel = null!;
    private Button      _btnAddFiles   = null!;
    private Button      _btnAddFolder  = null!;
    private Button      _btnRemove     = null!;
    private Button      _btnClear      = null!;
    private Button      _btnStart      = null!;
    private Button      _btnCancel     = null!;
    private Button      _btnOpenOut    = null!;
    private TextBox     _txtRules      = null!;
    private TextBox     _txtOutDir     = null!;
    private Label       _statusLabel   = null!;
    private Label       _statFiles     = null!;
    private Label       _statLines     = null!;
    private Label       _statHits      = null!;
    private Label       _statTime      = null!;
    private Label       _fileCountBadge = null!;

    // ── Colors (Ultra-Modern Dark Theme) ──────────────────────────────────────
    private static readonly Color BgMain    = Color.FromArgb(10,  14,  20);
    private static readonly Color BgCard    = Color.FromArgb(20,  25,  32);
    private static readonly Color BgHover   = Color.FromArgb(32,  38,  46);
    private static readonly Color Accent    = Color.FromArgb(88,  166, 255);
    private static readonly Color AccGreen  = Color.FromArgb(63,  185,  80);
    private static readonly Color AccRed    = Color.FromArgb(248,  81,  73);
    private static readonly Color AccYellow = Color.FromArgb(210, 153,  34);
    private static readonly Color Border    = Color.FromArgb(48,   54,  61);
    private static readonly Color TextMain  = Color.FromArgb(230, 237, 243);
    private static readonly Color TextMuted = Color.FromArgb(139, 148, 158);

    // ─────────────────────────────────────────────────────────────────────────
    public MainForm()
    {
        _rulesPath = FindRulesFile();
        _outDir    = AppDomain.CurrentDomain.BaseDirectory;
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        SuspendLayout();

        Text          = "日志审计工具";
        Size          = new Size(1320, 860);
        MinimumSize   = new Size(1024, 720);
        BackColor     = BgMain;
        ForeColor     = TextMain;
        Font          = new Font("Microsoft YaHei", 9.5f); // 切换为雅黑，中文渲染更好
        StartPosition = FormStartPosition.CenterScreen;
        Icon          = BuildIcon() ?? SystemIcons.Application;

        // ── Batched log timer ──
        _logTimer = new System.Windows.Forms.Timer { Interval = 60 };
        _logTimer.Tick += FlushLogQueue;
        _logTimer.Start();

        // ── Root layout ───────────────────────────────────────────────────────
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1, BackColor = BgMain,
            Margin = new Padding(0), Padding = new Padding(0)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(root);

        root.Controls.Add(BuildHeader(), 0, 0);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill, BackColor = BgMain, BorderStyle = BorderStyle.None,
            Margin = new Padding(12), SplitterWidth = 8
        };
        root.Controls.Add(split, 0, 1);
        split.Panel1.Controls.Add(BuildLeftPanel());
        split.Panel2.Controls.Add(BuildRightPanel());

        Load += (_, _) =>
        {
            split.Panel1MinSize    = 400;
            split.Panel2MinSize    = 300;
            split.SplitterDistance = Math.Clamp(460, 400, Math.Max(401, split.Width - 360));
        };

        // Initial log messages
        DirectLog($"[系统] 规则库加载目录: {_rulesPath}\n", TextMuted);
        DirectLog($"[系统] 审计报告输出至: {_outDir}\n", TextMuted);
        DirectLog("──────────────────────────────────────────\n", Border);
        DirectLog("正在等待任务... 支持将文件或文件夹直接拖拽至左侧列表区。\n", Accent);

        ResumeLayout(false);
        PerformLayout();
    }

    // ── Header ────────────────────────────────────────────────────────────────
    private Panel BuildHeader()
    {
        var hdr = new Panel { Dock = DockStyle.Fill, BackColor = BgCard };
        hdr.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var br = new LinearGradientBrush(hdr.ClientRectangle, BgCard, Color.FromArgb(15, 20, 30), LinearGradientMode.Horizontal);
            e.Graphics.FillRectangle(br, hdr.ClientRectangle);
            
            using var pen = new Pen(Border);
            e.Graphics.DrawLine(pen, 0, hdr.Height - 1, hdr.Width, hdr.Height - 1);
            using var ap = new Pen(Accent, 2);
            e.Graphics.DrawLine(ap, 0, hdr.Height - 1, 160, hdr.Height - 1);
        };
        
        var logo = new Label
        {
            Text = "🛡️ LogAudit", Font = new Font("Microsoft YaHei", 16f, FontStyle.Bold),
            ForeColor = TextMain, AutoSize = true, Location = new Point(20, 12), BackColor = Color.Transparent
        };
        var subText = new Label
        {
            Text = "日志分析工具", Font = new Font("Microsoft YaHei", 9f),
            ForeColor = TextMuted, AutoSize = true, Location = new Point(24, 46), BackColor = Color.Transparent
        };
        _statusLabel = new Label
        {
            Text = "● 系统就绪", Font = new Font("Microsoft YaHei", 10f, FontStyle.Bold),
            ForeColor = AccGreen, AutoSize = true, BackColor = Color.Transparent
        };
        
        hdr.Controls.Add(logo);
        hdr.Controls.Add(subText);
        hdr.Controls.Add(_statusLabel);
        hdr.Resize += (_, _) => _statusLabel.Location = new Point(hdr.Width - _statusLabel.Width - 30, 26);
        return hdr;
    }

    // ── Left Panel ────────────────────────────────────────────────────────────
    private Control BuildLeftPanel()
    {
        var tbl = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7,
            BackColor = BgMain, Padding = new Padding(0, 0, 8, 0),
        };
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 100)); // 给路径设置区留出足够高度
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));

        // Row 0: Header
        var hdrRow = new Panel { Dock = DockStyle.Fill, BackColor = BgMain };
        _fileCountBadge = new Label
        {
            Text = "0 个文件", ForeColor = Accent, AutoSize = true,
            Font = new Font("Microsoft YaHei", 9f, FontStyle.Bold), Dock = DockStyle.Right,
            TextAlign = ContentAlignment.MiddleRight, Padding = new Padding(0, 8, 0, 0)
        };
        var lblTitle = MkSectionLabel("📂 分析目标队列");
        lblTitle.Padding = new Padding(0, 6, 0, 0);
        hdrRow.Controls.Add(_fileCountBadge);
        hdrRow.Controls.Add(lblTitle);
        tbl.Controls.Add(hdrRow, 0, 0);

        // Row 1: File List
        _fileList = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details,
            FullRowSelect = true, MultiSelect = true,
            BackColor = BgCard, ForeColor = TextMain,
            BorderStyle = BorderStyle.None, Font = new Font("Microsoft YaHei", 9f),
            AllowDrop = true, OwnerDraw = true,
            Margin = new Padding(0, 4, 0, 8),
            SmallImageList = new ImageList { ImageSize = new Size(1, 32) } 
        };
        _fileList.Columns.Add("文件名", 180);
        _fileList.Columns.Add("大小", 80);
        _fileList.Columns.Add("绝对路径", 300);
        
        var sf = new StringFormat { LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter };
        
        _fileList.DrawColumnHeader += (_, e) =>
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var br = new SolidBrush(Color.FromArgb(15, 20, 26)); e.Graphics.FillRectangle(br, e.Bounds);
            using var p = new Pen(Border); e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            using var tb = new SolidBrush(TextMuted);
            using var f = new Font("Microsoft YaHei", 8.5f, FontStyle.Bold);
            e.Graphics.DrawString(e.Header?.Text ?? "", f, tb, new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width, e.Bounds.Height), sf);
        };
        _fileList.DrawItem += (_, e) =>
        {
            if (e.Item.Selected) { using var br = new SolidBrush(Color.FromArgb(25, 45, 65)); e.Graphics.FillRectangle(br, e.Bounds); }
        };
        _fileList.DrawSubItem += (_, e) =>
        {
            using var br = new SolidBrush(e.ColumnIndex == 0 ? (e.Item.Selected ? Color.White : Accent) : TextMuted);
            var rect = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 16, e.Bounds.Height);
            e.Graphics.DrawString(e.SubItem?.Text ?? "", _fileList.Font, br, rect, sf);
            using var lp = new Pen(Color.FromArgb(20, 25, 30));
            e.Graphics.DrawLine(lp, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
        };
        _fileList.DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        _fileList.DragDrop += (_, e) => { if (e.Data?.GetData(DataFormats.FileDrop) is string[] fs) AddPaths(fs); };
        tbl.Controls.Add(_fileList, 0, 1);

        // Row 2: File Buttons
        var br2 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = BgMain, Margin = new Padding(0) };
        for (int i = 0; i < 4; i++) br2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        _btnAddFiles  = MkBtn("＋ 添加文件", Color.FromArgb(25, 60, 100), Accent);
        _btnAddFolder = MkBtn("＋ 添加目录", Color.FromArgb(30, 40, 60), TextMain);
        _btnRemove    = MkBtn("－ 移除选中", Color.FromArgb(60, 30, 35), AccRed);
        _btnClear     = MkBtn("× 清空列表", Color.FromArgb(60, 30, 35), AccRed);
        br2.Controls.Add(_btnAddFiles,  0, 0); br2.Controls.Add(_btnAddFolder, 1, 0);
        br2.Controls.Add(_btnRemove,    2, 0); br2.Controls.Add(_btnClear,     3, 0);
        
        _btnAddFiles.Click  += (_, _) => BrowseFiles();
        _btnAddFolder.Click += (_, _) => BrowseFolder();
        _btnRemove.Click    += (_, _) => RemoveSelected();
        _btnClear.Click     += (_, _) => { _files.Clear(); RefreshList(); };
        tbl.Controls.Add(br2, 0, 2);

        // Row 3: Settings (彻底修复文本框被挤压的问题)
        var sg = new TableLayoutPanel { 
            Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2, 
            BackColor = BgMain, Margin = new Padding(0, 10, 0, 10) 
        };
        // 第一列：标签（固定宽度，保证中文字不换行）
        sg.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        // 第二列：文本框（占据剩余全部空间）
        sg.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        // 第三列：按钮（固定宽度）
        sg.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 40));
        
        sg.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        sg.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        _txtRules  = MkTextBox(_rulesPath);
        _txtOutDir = MkTextBox(_outDir);
        var bRules = MkSmallBtn("···"); var bOut = MkSmallBtn("···");
        
        bRules.Click += (_, _) => { using var d = new OpenFileDialog { Filter = "YAML 规则|*.yaml;*.yml|所有文件|*.*" }; if (d.ShowDialog() == DialogResult.OK) { _rulesPath = d.FileName; _txtRules.Text = d.FileName; } };
        bOut.Click += (_, _) => { using var d = new FolderBrowserDialog { SelectedPath = _outDir }; if (d.ShowDialog() == DialogResult.OK) { _outDir = d.SelectedPath; _txtOutDir.Text = d.SelectedPath; } };
        
        sg.Controls.Add(MkLabel("规则文件:", TextMuted), 0, 0); sg.Controls.Add(_txtRules,  1, 0); sg.Controls.Add(bRules, 2, 0);
        sg.Controls.Add(MkLabel("输出目录:", TextMuted), 0, 1); sg.Controls.Add(_txtOutDir, 1, 1); sg.Controls.Add(bOut,   2, 1);
        tbl.Controls.Add(sg, 0, 3);

        // Row 4: Start
        _btnStart = new Button
        {
            Text = "⚡ 开始分析", Dock = DockStyle.Fill,
            Font = new Font("Microsoft YaHei", 12f, FontStyle.Bold),
            ForeColor = Color.White, BackColor = Color.FromArgb(40, 145, 65),
            FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
            Margin = new Padding(0, 0, 0, 4)
        };
        _btnStart.FlatAppearance.BorderSize = 0;
        AttachHover(_btnStart, Color.FromArgb(40, 145, 65), Color.FromArgb(50, 165, 80));
        _btnStart.Click += (_, _) => _ = StartAnalysisAsync();
        tbl.Controls.Add(_btnStart, 0, 4);

        // Row 5: Cancel + Open
        var ar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = BgMain, Margin = new Padding(0) };
        ar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50)); ar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _btnCancel = MkBtn("⏹ 终止任务", BgHover, TextMuted); _btnCancel.Enabled = false;
        _btnCancel.Click += (_, _) => _cts?.Cancel();
        _btnOpenOut = MkBtn("📂 打开输出目录", BgHover, Accent);
        _btnOpenOut.Click += (_, _) => Process.Start("explorer", _outDir);
        ar.Controls.Add(_btnCancel,  0, 0); ar.Controls.Add(_btnOpenOut, 1, 0);
        tbl.Controls.Add(ar, 0, 5);

        // Row 6: Stats
        var sr = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = BgCard, Margin = new Padding(0, 10, 0, 0) };
        for (int i = 0; i < 4; i++) sr.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        _statFiles = MkStat("--", "分析文件"); _statLines = MkStat("--", "解析行数"); _statHits = MkStat("--", "发现告警"); _statTime = MkStat("--", "执行耗时");
        sr.Controls.Add(_statFiles, 0, 0); sr.Controls.Add(_statLines, 1, 0); sr.Controls.Add(_statHits,  2, 0); sr.Controls.Add(_statTime,  3, 0);
        tbl.Controls.Add(sr, 0, 6);

        return tbl;
    }

    // ── Right Panel ───────────────────────────────────────────────────────────
    private Control BuildRightPanel()
    {
        var tbl = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3,
            BackColor = BgMain, Padding = new Padding(8, 0, 0, 0),
        };
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));

        var lblTitle = MkSectionLabel("📟 运行日志");
        lblTitle.Padding = new Padding(0, 6, 0, 0);
        tbl.Controls.Add(lblTitle, 0, 0);

        var logContainer = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(12, 16, 22), Padding = new Padding(12) };
        _log = new RichTextBox
        {
            Dock = DockStyle.Fill, BackColor = Color.FromArgb(12, 16, 22),
            ForeColor = TextMain, Font = new Font("Cascadia Code", 9.5f, FontStyle.Regular),
            ReadOnly = true, BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Vertical, WordWrap = false,
        };
        logContainer.Controls.Add(_log);
        tbl.Controls.Add(logContainer, 0, 1);

        var pp = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = BgMain, Margin = new Padding(0) };
        pp.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); pp.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        
        _progressLabel = new Label
        {
            Dock = DockStyle.Fill, Text = "系统空闲中...",
            ForeColor = TextMuted, Font = new Font("Microsoft YaHei", 9f),
            TextAlign = ContentAlignment.BottomLeft,
        };
        _progress = new ModernProgressBar { Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4) };
        
        pp.Controls.Add(_progressLabel, 0, 0); pp.Controls.Add(_progress, 0, 1);
        tbl.Controls.Add(pp, 0, 2);

        return tbl;
    }

    // ── Custom Controls & UI Helpers ──────────────────────────────────────────
    
    private class ModernProgressBar : Control
    {
        private float _val;
        public float Value { get { return _val; } set { _val = Math.Clamp(value, 0, 100); Invalidate(); } }
        public ModernProgressBar() { DoubleBuffered = true; }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using var trackBr = new SolidBrush(Color.FromArgb(20, 25, 32));
            using var path = GetRoundedRect(rect, 4);
            e.Graphics.FillPath(trackBr, path);
            
            if (_val > 0)
            {
                var fillWidth = (int)((_val / 100f) * Width);
                if (fillWidth > 0)
                {
                    var fillRect = new Rectangle(0, 0, fillWidth, Height);
                    using var fillPath = GetRoundedRect(fillRect, 4);
                    using var fillBr = new LinearGradientBrush(fillRect, Color.FromArgb(25, 100, 200), Accent, LinearGradientMode.Horizontal);
                    e.Graphics.FillPath(fillBr, fillPath);
                }
            }
        }
        private GraphicsPath GetRoundedRect(Rectangle bounds, int radius)
        {
            int diameter = radius * 2;
            Size size = new Size(diameter, diameter);
            Rectangle arc = new Rectangle(bounds.Location, size);
            GraphicsPath path = new GraphicsPath();

            if (radius == 0) { path.AddRectangle(bounds); return path; }

            path.AddArc(arc, 180, 90); arc.X = bounds.Right - diameter;
            path.AddArc(arc, 270, 90); arc.Y = bounds.Bottom - diameter;
            path.AddArc(arc, 0, 90);   arc.X = bounds.Left;
            path.AddArc(arc, 90, 90);  path.CloseFigure();
            return path;
        }
    }

    private static void AttachHover(Button btn, Color normal, Color hover)
    {
        btn.MouseEnter += (_, _) => { if (btn.Enabled) btn.BackColor = hover; };
        btn.MouseLeave += (_, _) => { if (btn.Enabled) btn.BackColor = normal; };
        btn.EnabledChanged += (_, _) => btn.BackColor = btn.Enabled ? normal : BgHover;
    }

    private static Button MkBtn(string text, Color bg, Color fg)
    {
        var b = new Button
        {
            Text = text, Dock = DockStyle.Fill,
            Font = new Font("Microsoft YaHei", 9f, FontStyle.Bold),
            BackColor = bg, ForeColor = fg,
            FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
            Margin = new Padding(0, 0, 4, 0),
        };
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = bg;
        b.FlatAppearance.MouseDownBackColor = Color.FromArgb(bg.R / 2, bg.G / 2, bg.B / 2);
        
        var hoverBg = Color.FromArgb(Math.Min(255, bg.R + 20), Math.Min(255, bg.G + 20), Math.Min(255, bg.B + 20));
        AttachHover(b, bg, hoverBg);
        return b;
    }

    private static Button MkSmallBtn(string text)
    {
        var b = new Button
        {
            Text = text, Dock = DockStyle.Fill,
            Font = new Font("Microsoft YaHei", 9f, FontStyle.Bold),
            BackColor = BgCard, ForeColor = TextMuted,
            FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = Border;
        AttachHover(b, BgCard, BgHover);
        return b;
    }

    private static TextBox MkTextBox(string text) => new()
    {
        Text = text, Dock = DockStyle.Fill,
        BackColor = BgCard, ForeColor = TextMain,
        Font = new Font("Consolas", 9.5f),
        BorderStyle = BorderStyle.FixedSingle,
        Margin = new Padding(0, 6, 8, 6), // 增加右侧间距，防拥挤
        AutoSize = false,                 // 【核心修复】关闭自动调整，强制高度
        Height = 26
    };

    private static Label MkSectionLabel(string text) => new()
    {
        Text = text, Font = new Font("Microsoft YaHei", 10f, FontStyle.Bold),
        ForeColor = TextMain, AutoSize = true
    };

    private static Label MkLabel(string text, Color color) => new()
    {
        Text = text, ForeColor = color, Dock = DockStyle.Fill,
        Font = new Font("Microsoft YaHei", 9f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft,
        Padding = new Padding(2, 0, 2, 0)
    };

    private static Label MkStat(string val, string lbl)
    {
        var panel = new Label { Dock = DockStyle.Fill, BackColor = BgCard, Padding = new Padding(0, 10, 0, 6) };
        var valLbl = new Label
        {
            Text = val, Tag = "val",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = Accent, Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.BottomCenter,
            BackColor = Color.Transparent,
        };
        var lblLbl = new Label
        {
            Text = lbl, Tag = "lbl",
            Font = new Font("Microsoft YaHei", 8.5f, FontStyle.Bold),
            ForeColor = TextMuted, Dock = DockStyle.Bottom, Height = 20,
            TextAlign = ContentAlignment.TopCenter,
            BackColor = Color.Transparent,
        };
        panel.Controls.Add(valLbl); panel.Controls.Add(lblLbl);
        return panel;
    }

    // ── Batched log flush ─────────────────────────────────────────────────────
    private void FlushLogQueue(object? sender, EventArgs e)
    {
        if (_logQueue.IsEmpty) return;
        _log.SuspendLayout();
        int count = 0;
        while (_logQueue.TryDequeue(out var item) && count++ < 200)
        {
            _log.SelectionStart  = _log.TextLength;
            _log.SelectionLength = 0;
            _log.SelectionColor  = item.color;
            _log.AppendText(item.text);
        }
        _log.ResumeLayout();
        _log.ScrollToCaret();
    }

    private void AppendLog(string text, Color color) => _logQueue.Enqueue((text, color));
    private void DirectLog(string text, Color color) { _log.SelectionStart = _log.TextLength; _log.SelectionLength = 0; _log.SelectionColor = color; _log.AppendText(text); }

    // ── File helpers ──────────────────────────────────────────────────────────
    private void BrowseFiles() { using var d = new OpenFileDialog { Multiselect = true, Title = "选择日志文件", Filter = "日志文件|*.log;*.txt;*.access;*.gz|所有文件|*.*" }; if (d.ShowDialog() == DialogResult.OK) AddPaths(d.FileNames); }
    private void BrowseFolder() { using var d = new FolderBrowserDialog { Description = "选择日志目录" }; if (d.ShowDialog() == DialogResult.OK) AddPaths([d.SelectedPath]); }
    private void AddPaths(string[] paths)
    {
        int added = 0;
        foreach (var p in paths)
        {
            if (Directory.Exists(p)) { foreach (var f in Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories)) { var ext = Path.GetExtension(f).ToLowerInvariant(); var name = Path.GetFileName(f).ToLowerInvariant(); if (ext is ".log" or ".txt" or ".access" or ".gz" || name.Contains("access") || name.Contains("error")) if (AddUnique(f)) added++; } }
            else if (File.Exists(p)) { if (AddUnique(p)) added++; }
        }
        if (added > 0) { RefreshList(); AppendLog($"[+] 成功添加 {added} 个文件，当前共计: {_files.Count}\n", AccGreen); }
    }
    private bool AddUnique(string f) { if (_files.Contains(f)) return false; _files.Add(f); return true; }
    private void RemoveSelected() { foreach (var f in _fileList.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as string).Where(f => f != null).ToList()) _files.Remove(f!); RefreshList(); }
    private void RefreshList()
    {
        _fileList.Items.Clear();
        foreach (var f in _files)
        {
            var fi = new FileInfo(f); var item = new ListViewItem(fi.Name) { Tag = f };
            item.SubItems.Add(FmtSize(fi.Exists ? fi.Length : 0)); item.SubItems.Add(fi.DirectoryName ?? "");
            _fileList.Items.Add(item);
        }
        _fileCountBadge.Text = $"{_files.Count} 个文件";
    }

    // ── Analysis ──────────────────────────────────────────────────────────────
    private async Task StartAnalysisAsync()
    {
        if (_files.Count == 0) { MessageBox.Show("请先添加待分析的日志文件！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        _rulesPath = _txtRules.Text.Trim(); _outDir = _txtOutDir.Text.Trim();
        if (!File.Exists(_rulesPath)) { MessageBox.Show($"找不到规则配置文件:\n{_rulesPath}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
        if (!Directory.Exists(_outDir)) Directory.CreateDirectory(_outDir);

        SetRunState(true);
        _cts = new CancellationTokenSource();
        _log.Clear(); _logQueue.Clear();
        var sw = Stopwatch.StartNew();

        try
        {
            AppendLog($"[*] 目标文件总数: {_files.Count}\n", TextMain);
            AppendLog($"[*] 规则库路径:   {_rulesPath}\n", TextMuted);
            AppendLog($"[*] 报告输出目录: {_outDir}\n", TextMuted);
            AppendLog($"[*] 任务启动时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n", TextMuted);

            SetProg(5, "正在加载特征库..."); SetStatus("● 加载规则", AccYellow);

            RuleEngine engine;
            try { engine = await Task.Run(() => RuleEngine.Load(_rulesPath)); AppendLog($"[+] 特征库加载完成 (成功加载 {engine.Rules.Count} 条特征)\n\n", AccGreen); }
            catch (Exception ex) { AppendLog($"[-] 特征库加载失败: {ex.Message}\n", AccRed); MessageBox.Show($"规则文件格式有误:\n{ex.Message}", "错误"); return; }

            var scanner = new FileScanner(engine); var secReporter = new SecurityReporter(); var analyzer = new StreamingAnalyzer();
            long totalLines = 0, totalHits = 0;

            SetProg(10, "正在分析..."); SetStatus("● 分析中", AccYellow);

            for (int i = 0; i < _files.Count; i++)
            {
                if (_cts.Token.IsCancellationRequested) break;
                var fpath = _files[i]; var fname = Path.GetFileName(fpath);
                AppendLog($"[分析] {fname}\n", Accent);

                var chunkProgress = new Progress<(long bytesRead, long totalBytes, long linesProcessed)>(p =>
                {
                    int filePct = p.totalBytes > 0 ? (int)((double)p.bytesRead / p.totalBytes * 100) : 0;
                    int globalPct = 10 + (int)((i + filePct / 100.0) / _files.Count * 70);
                    SetProg(Math.Clamp(globalPct, 10, 79), $"[{i + 1}/{_files.Count}] {fname}  {filePct}%  ({FmtSize(p.bytesRead)}/{FmtSize(p.totalBytes)})  行数:{p.linesProcessed:N0}");
                });

                try
                {
                    var result = await scanner.ScanFileAsync(fpath, (entries, hits) => { analyzer.Feed(entries); foreach (var h in hits) secReporter.Add(h); }, chunkProgress, _cts.Token);
                    totalLines += result.TotalLines; totalHits += result.Hits.Count;

                    AppendLog($"   >> 行数:{result.TotalLines:N0}  触发告警:{result.Hits.Count}  体积:{FmtSize(result.FileSize)}\n", TextMuted);
                    if (result.Hits.Count > 0)
                    {
                        var crit = result.Hits.Count(h => h.Rule.Severity == Severity.Critical); var high = result.Hits.Count(h => h.Rule.Severity == Severity.High); var med = result.Hits.Count(h => h.Rule.Severity == Severity.Medium);
                        AppendLog($"   >> [! 严重:{crit} | 高危:{high} | 中危:{med} ]\n", AccYellow);
                    }
                    SetStats(_files.Count, (int)totalLines, (int)totalHits, sw.Elapsed.TotalSeconds);
                }
                catch (OperationCanceledException) { AppendLog("[-] 用户手动终止任务\n", AccYellow); break; }
                catch (Exception ex) { AppendLog($"[-] 扫描跳过: {ex.Message}\n", AccRed); }
            }

            if (_cts.Token.IsCancellationRequested) { AppendLog("\n[-] 任务已中止\n", AccYellow); SetStatus("● 已中止", AccYellow); return; }

            AppendLog($"\n[*] 分析完毕. 总计解析行数: {totalLines:N0}\n", TextMain);
            SetProg(82, "正在聚合数据..."); SetStatus("● 聚合报告", AccYellow);

            var ar = await Task.Run(() => analyzer.BuildResult()); var sr = await Task.Run(() => secReporter.Build());

            var baseName = _files.Count == 1 ? Path.GetFileNameWithoutExtension(_files[0]) : "logaudit";
            var reportTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var fileDisplay = _files.Count == 1 ? Path.GetFileName(_files[0]) : $"{_files.Count} 个文件";
            var elapsed = sw.Elapsed; var duration = elapsed.TotalSeconds < 60 ? $"{elapsed.TotalSeconds:F2}s" : $"{(int)elapsed.TotalMinutes}m{elapsed.Seconds:D2}s";
            var trafficPath = Path.Combine(_outDir, $"{baseName}-流量分析报告.html"); var secPath = Path.Combine(_outDir, $"{baseName}-安全分析报告.html");

            SetProg(94, "正在生成流量报告...");
            await File.WriteAllTextAsync(trafficPath, await Task.Run(() => TrafficReportGenerator.Generate(ar, reportTime, fileDisplay, duration)), System.Text.Encoding.UTF8);
            AppendLog($"[+] 流量分析报告 -> {Path.GetFileName(trafficPath)}\n", AccGreen);

            SetProg(97, "正在生成安全报告...");
            await File.WriteAllTextAsync(secPath, await Task.Run(() => SecurityReportGenerator.Generate(sr, reportTime, fileDisplay, duration)), System.Text.Encoding.UTF8);
            AppendLog($"[+] 安全分析报告 -> {Path.GetFileName(secPath)}\n", AccGreen);

            SetProg(100, "全部分析工作流已完成。"); SetStatus("● 分析完成", AccGreen);
            SetStats(_files.Count, (int)totalLines, sr.TotalHits, sw.Elapsed.TotalSeconds);

            AppendLog("\n██████████████████████████████████████████████████████\n", AccGreen);
            AppendLog("  [✔] 分析完成\n", AccGreen);
            AppendLog($"  处理耗时: {duration}\n", TextMain);
            AppendLog($"  请求总数: {ar.TotalRequests:N0}  |  告警总数: {sr.TotalHits:N0}\n", TextMain);
            AppendLog($"  [ 严重:{sr.CriticalCount} | 高危:{sr.HighCount} | 中危:{sr.MediumCount} | 低危:{sr.LowCount} ]\n", sr.CriticalCount > 0 ? AccRed : AccYellow);
            AppendLog("██████████████████████████████████████████████████████\n", AccGreen);

            FlushLogQueue(null, EventArgs.Empty);
            if (MessageBox.Show($"✅ 分析完成！\n\n流量报告: {Path.GetFileName(trafficPath)}\n安全报告: {Path.GetFileName(secPath)}\n\n耗时: {duration} | 总请求: {ar.TotalRequests:N0} | 命中告警: {sr.TotalHits:N0}\n\n是否立即打开报告所在目录？", "任务完成", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes) Process.Start("explorer", _outDir);
        }
        catch (Exception ex) { AppendLog($"\n[-] 发生致命错误: {ex.Message}\n", AccRed); SetStatus("● 系统错误", AccRed); MessageBox.Show($"分析过程中断:\n{ex.Message}", "严重错误", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { SetRunState(false); }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────
    private void SetRunState(bool running)
    {
        _btnStart.Enabled = !running; _btnStart.BackColor = running ? Color.FromArgb(25, 35, 25) : Color.FromArgb(40, 145, 65);
        _btnCancel.Enabled = running; _btnAddFiles.Enabled = !running; _btnAddFolder.Enabled = !running;
    }
    private void SetProg(int value, string label) { _progress.Value = value; _progressLabel.Text = label; }
    private void SetStatus(string text, Color color) { _statusLabel.Text = text; _statusLabel.ForeColor = color; }
    private void SetStats(int files, int lines, int hits, double secs)
    {
        SetStat(_statFiles, files.ToString(), "分析文件"); SetStat(_statLines, FmtCount(lines), "解析行数");
        SetStat(_statHits, hits.ToString(), "发现告警"); SetStat(_statTime, $"{secs:F1}s", "执行耗时");
        var v = _statHits.Controls.OfType<Label>().FirstOrDefault(l => l.Tag as string == "val");
        if (v != null) v.ForeColor = hits > 0 ? AccRed : AccGreen;
    }
    private static void SetStat(Label panel, string val, string lbl) { foreach (Label l in panel.Controls.OfType<Label>()) { if (l.Tag as string == "val") l.Text = val; if (l.Tag as string == "lbl") l.Text = lbl; } }

    // ── Utilities ─────────────────────────────────────────────────────────────
    private static string FmtSize(long b) => b switch { >= 1L << 30 => $"{(double)b / (1L << 30):F1} GB", >= 1L << 20 => $"{(double)b / (1L << 20):F1} MB", >= 1L << 10 => $"{(double)b / (1L << 10):F0} KB", _ => $"{b} B" };
    private static string FmtCount(int n) => n >= 1_000_000 ? $"{n / 1_000_000.0:F1}M" : n >= 1000 ? $"{n / 1000.0:F1}K" : n.ToString();
    private static string FindRulesFile() { var d = AppDomain.CurrentDomain.BaseDirectory; string[] c = [Path.Combine(d, "rules", "rules.yaml"), Path.Combine(d, "rules.yaml"), "rules\\rules.yaml"]; return c.FirstOrDefault(File.Exists) ?? c[0]; }
    private static Icon? BuildIcon() { try { using var bmp = new Bitmap(64, 64); using var g = Graphics.FromImage(bmp); g.SmoothingMode = SmoothingMode.AntiAlias; using var br = new LinearGradientBrush(new Rectangle(0, 0, 64, 64), Accent, Color.FromArgb(188, 140, 255), 135f); g.FillRectangle(br, 0, 0, 64, 64); return Icon.FromHandle(bmp.GetHicon()); } catch { return null; } }
}