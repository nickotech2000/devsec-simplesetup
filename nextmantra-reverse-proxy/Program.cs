/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

sealed class Args(string[] a)
{
    public bool Has(string n) => a.Any(x => x.Equals("--" + n, StringComparison.OrdinalIgnoreCase) || (n.Length == 1 && x == "-" + n));
    public bool Any(params string[] n) => n.Any(Has);

    public string? Value(string n)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i].StartsWith("--" + n + "=", StringComparison.OrdinalIgnoreCase)) return a[i][(n.Length + 3)..];
            if (a[i].Equals("--" + n, StringComparison.OrdinalIgnoreCase) && i + 1 < a.Length && !a[i + 1].StartsWith('-')) return a[i + 1];
        }
        return null;
    }
}

static class Program
{
    const string MutexId = "Global\\AgantraInovatifPkiProxySingletonId_777";
    static Mutex? appMutex;

    public static void Banner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("-------------------------------------------------");
        Console.WriteLine("Author  : Nicko Satria Utama");
        Console.WriteLine("Company : Agantra Inovatif OU");
        Console.WriteLine("Email   : nicko@nextmantra.com");
        Console.WriteLine("-------------------------------------------------");
        Console.ResetColor();
    }

    static void Help()
    {
        Console.WriteLine("""
            Agantra PKI proxy: CRL/OCSP reverse proxy, HTTP forward proxy (CONNECT), TCP relay. Raw sockets, no logging, small cache.

            Run:            (no switch)            run in the foreground, Ctrl+C stops it
                            --service              run as a service (used by the installers)
                            --config <file>        appsettings.json to use (default: next to the executable)
            Control:        --status | --reload | --stop (alias --kill, -k)
            Hosts file:     --hosts-add | --hosts-remove | --hosts-status
                            --ip <addr> (default 127.0.0.1)  --ipv6  --dry-run  --hosts-file <path>
            Windows:        --install-service | --uninstall-service     (add --with-hosts to also edit the hosts file)
            Linux systemd:  --install-systemd | --uninstall-systemd     (add --with-hosts)
            Install/hosts switches need Administrator or root.
            """);
    }

    static async Task<int> Main(string[] argv)
    {
        var a = new Args(argv);
        if (a.Any("help", "h", "?")) { Banner(); Help(); return 0; }
        if (a.Any("stop", "kill", "k")) return Control.Client("stop");
        if (a.Has("status")) return Control.Client("status");
        if (a.Has("reload")) return Control.Client("reload");
        if (a.Any("hosts-add", "hosts-remove", "hosts-status")) return Hosts.Run(a);
        if (a.Any("install-service", "uninstall-service", "install-systemd", "uninstall-systemd")) return Installer.Run(a);

        bool svc = a.Has("service");
        string cfgPath = Paths.Config(a);

        try { appMutex = new Mutex(true, MutexId, out bool isNew); if (!isNew) { Console.Error.WriteLine("An instance of this proxy is already running."); return 1; } }
        catch { /* no permission on the named mutex: the port bind below still protects against a second instance */ }

        if (svc && OperatingSystem.IsWindows())
        {
            int r = WinService.Run(cfgPath);
            if (r >= 0) return r;   // -1: not started by the service manager, run as a console
        }
        return await Foreground(cfgPath, svc);
    }

    static async Task<int> Foreground(string cfgPath, bool quiet)
    {
        if (!quiet) Banner();
        try { Server.Start(cfgPath); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("START FAILURE: " + ex.Message);
            return 1;
        }
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; Server.Quit.Cancel(); };
        PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; Server.Quit.Cancel(); });
        Control.Serve();
        if (!quiet)
        {
            Console.WriteLine(Server.Summary());
            Console.WriteLine("Stop with Ctrl+C, or run: --stop");
        }
        try { await Task.Delay(Timeout.Infinite, Server.Quit.Token); } catch (OperationCanceledException) { }
        Server.StopAll();
        return 0;
    }
}

// ===== listeners =====
static class Server
{
    public static readonly CancellationTokenSource Quit = new();
    static readonly object gate = new();
    static List<(TcpListener L, CancellationTokenSource Cts)> running = new();
    static string cfgPath = "";
    static Config current = new();

    public static void Start(string path)
    {
        cfgPath = path;
        current = Config.Load(path);
        Cache.Init(current.Cache);
        lock (gate) Bring(current);
    }

    static void Bring(Config cfg)
    {
        var started = new List<(TcpListener L, CancellationTokenSource Cts)>();
        try
        {
            foreach (var l in cfg.Listeners)
            {
                var tl = new TcpListener(l.Bind);
                tl.Start(512);
                var cts = new CancellationTokenSource();
                started.Add((tl, cts));
                _ = Accept(tl, l, cts.Token);
            }
        }
        catch (Exception ex)
        {
            foreach (var (tl, cts) in started) { cts.Cancel(); tl.Stop(); }
            throw new InvalidOperationException(ex.Message + " (is the port in use, or are you missing Administrator/root?)");
        }
        running = started;
    }

    static void StopListeners()
    {
        foreach (var (tl, cts) in running) { cts.Cancel(); try { tl.Stop(); } catch { } }
        running = new();
    }

    public static void StopAll() { lock (gate) StopListeners(); }

    public static string Reload()
    {
        lock (gate)
        {
            Config next;
            try { next = Config.Load(cfgPath); } catch (Exception ex) { return "ERROR: " + ex.Message; }
            StopListeners();
            try { Bring(next); current = next; return "OK"; }
            catch (Exception ex)
            {
                try { Bring(current); } catch { }
                return "ERROR: " + ex.Message + " (kept the previous settings)";
            }
        }
    }

    public static string Summary() =>
        string.Join("\n", current.Listeners.Select(l => $"[{l.Name}] {l.Mode} on {l.Bind}" +
            (l.Mode == "http-reverse" ? " -> " + string.Join(", ", l.Routes.Select(r => r.Key + "=>" + r.Value.Host)) : l.Mode == "tcp" ? $" -> {l.TargetHost}:{l.TargetPort}" : "")));

    static async Task Accept(TcpListener tl, Listener l, CancellationToken ct)
    {
        var slots = new SemaphoreSlim(l.MaxConnections);
        while (!ct.IsCancellationRequested)
        {
            Socket c;
            try { c = await tl.AcceptSocketAsync(ct); }
            catch when (ct.IsCancellationRequested) { break; }
            catch { await Task.Delay(50); continue; }

            var ip = (c.RemoteEndPoint as IPEndPoint)?.Address;
            if (ip == null || !l.Allows(ip) || !slots.Wait(0))
            {
                Interlocked.Increment(ref Stats.Rejected);
                c.Dispose();
                continue;
            }
            c.NoDelay = true;
            _ = Task.Run(async () =>
            {
                Interlocked.Increment(ref Stats.Active);
                try { await Handlers.Run(c, l, Quit.Token); }
                catch { Interlocked.Increment(ref Stats.Errors); }
                finally { c.Dispose(); slots.Release(); Interlocked.Decrement(ref Stats.Active); }
            });
        }
    }
}

// ===== control channel: named pipe (Windows) / unix socket (Linux, macOS), owner-only =====
static class Control
{
    const string PipeName = "agantra-pkiproxy-control";
    static string? sockFile;

    static string[] UnixPaths() => ["/run/pkiproxy/control.sock", Path.Combine(Path.GetTempPath(), "pkiproxy-" + Environment.UserName + ".sock")];

    public static void Serve()
    {
        if (OperatingSystem.IsWindows()) _ = Task.Run(ServePipe);
        else _ = Task.Run(ServeUnix);
    }

    [SupportedOSPlatform("windows")]
    static async Task ServePipe()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        var me = WindowsIdentity.GetCurrent().User;   // the account that runs the proxy (a non-elevated console, or LocalService)
        if (me != null) ps.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        while (!Server.Quit.IsCancellationRequested)
        {
            try
            {
                using var p = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, ps);
                await p.WaitForConnectionAsync(Server.Quit.Token);
                bool stop = await Handle(p);
                try { p.WaitForPipeDrain(); } catch { }
                if (stop) Server.Quit.Cancel();
            }
            catch (OperationCanceledException) { return; }
            catch (IOException) { await Task.Delay(500); }
            catch { return; }
        }
    }

    static async Task ServeUnix()
    {
        foreach (var path in UnixPaths())
        {
            try
            {
                if (!Directory.Exists(Path.GetDirectoryName(path))) continue;
                if (File.Exists(path)) File.Delete(path);
                using var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                s.Bind(new UnixDomainSocketEndPoint(path));
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                sockFile = path;
                s.Listen(4);
                while (!Server.Quit.IsCancellationRequested)
                {
                    using var c = await s.AcceptAsync(Server.Quit.Token);
                    using var ns = new NetworkStream(c, false);
                    if (await Handle(ns)) { Server.Quit.Cancel(); break; }
                }
                break;
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
        try { if (sockFile != null) File.Delete(sockFile); } catch { }
    }

    static async Task<bool> Handle(Stream s)
    {
        try
        {
            var buf = new byte[64];
            int n = 0;
            using var t = new CancellationTokenSource(2000);
            while (n < buf.Length - 1)
            {
                if (await s.ReadAsync(buf.AsMemory(n, 1), t.Token) == 0) break;
                if (buf[n] == (byte)'\n') break;
                n++;
            }
            var cmd = Encoding.ASCII.GetString(buf, 0, n).Trim().ToLowerInvariant();
            string reply = cmd switch
            {
                "ping" => "pong",
                "status" => Stats.Text(),
                "reload" => Server.Reload(),
                "stop" => "stopping",
                _ => "unknown command",
            };
            await s.WriteAsync(Encoding.UTF8.GetBytes(reply + "\n"));
            await s.FlushAsync();
            return cmd == "stop";
        }
        catch { return false; }
    }

    public static int Client(string cmd)
    {
        var reply = Send(cmd);
        if (reply == null) { Console.Error.WriteLine("The proxy is not running (or you lack the rights to reach it)."); return 1; }
        Console.Write(reply);
        return reply.StartsWith("ERROR") ? 1 : 0;
    }

    static string? Send(string cmd)
    {
        try
        {
            Stream s;
            if (OperatingSystem.IsWindows())
            {
                var p = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
                p.Connect(1500);
                s = p;
            }
            else
            {
                Socket? sock = null;
                foreach (var path in UnixPaths())
                {
                    if (!File.Exists(path)) continue;
                    var c = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    try { c.Connect(new UnixDomainSocketEndPoint(path)); sock = c; break; } catch { c.Dispose(); }
                }
                if (sock == null) return null;
                s = new NetworkStream(sock, true);
            }
            using (s)
            {
                s.Write(Encoding.ASCII.GetBytes(cmd + "\n"));
                s.Flush();
                using var r = new StreamReader(s, Encoding.UTF8);
                return r.ReadToEnd();
            }
        }
        catch { return null; }
    }
}

// ===== Windows service host (direct service-control API, no extra packages) =====
[SupportedOSPlatform("windows")]
static class WinService
{
    public const string Name = "AgantraPkiProxy";

    delegate void ServiceMainProc(int argc, IntPtr argv);
    delegate int HandlerEx(int control, int eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatus
    {
        public int ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool StartServiceCtrlDispatcherW(IntPtr table);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr RegisterServiceCtrlHandlerExW(string name, HandlerEx handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus status);

    static readonly ServiceMainProc mainProc = ServiceMain;   // fields keep the delegates alive
    static readonly HandlerEx handlerProc = Handler;
    static IntPtr handle;
    static string cfgPath = "";

    // -1: this process was not started by the service manager.
    public static int Run(string path)
    {
        cfgPath = path;
        int sz = IntPtr.Size;
        IntPtr table = Marshal.AllocHGlobal(sz * 4);
        Marshal.WriteIntPtr(table, 0, Marshal.StringToHGlobalUni(Name));
        Marshal.WriteIntPtr(table, sz, Marshal.GetFunctionPointerForDelegate(mainProc));
        Marshal.WriteIntPtr(table, sz * 2, IntPtr.Zero);
        Marshal.WriteIntPtr(table, sz * 3, IntPtr.Zero);
        if (StartServiceCtrlDispatcherW(table)) return 0;
        return Marshal.GetLastWin32Error() == 1063 ? -1 : 1;
    }

    static void Set(int state, int accepted = 0, int exitCode = 0, int waitHint = 0)
    {
        var st = new ServiceStatus { ServiceType = 0x10, CurrentState = state, ControlsAccepted = accepted, Win32ExitCode = exitCode, WaitHint = waitHint };
        SetServiceStatus(handle, ref st);
    }

    static int Handler(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        if (control is 1 or 5) Server.Quit.Cancel();   // STOP, SHUTDOWN
        return 0;
    }

    static void ServiceMain(int argc, IntPtr argv)
    {
        handle = RegisterServiceCtrlHandlerExW(Name, handlerProc, IntPtr.Zero);
        Set(2, waitHint: 10000);
        try { Server.Start(cfgPath); Control.Serve(); }
        catch { Set(1, exitCode: 1); return; }
        Set(4, accepted: 5);   // RUNNING, accepts STOP and SHUTDOWN
        Server.Quit.Token.WaitHandle.WaitOne();
        Set(3, waitHint: 5000);
        Server.StopAll();
        Set(1);
    }
}
