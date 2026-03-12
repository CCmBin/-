using System.Runtime.Versioning;
using System.Windows.Forms;
using LogAudit.GUI;

[assembly: SupportedOSPlatform("windows")]

internal static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        try
        {
            Application.Run(new MainForm());
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "启动失败:\n\n" + ex.Message + "\n\n" + ex.StackTrace,
                "LogAudit 启动错误",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
