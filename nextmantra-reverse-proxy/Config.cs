/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

// ===== appsettings.json model (PkiProxySettings). Routes/Bind/Allow at the top level describe the default PKI listener =====
sealed class Root { public Settings? PkiProxySettings { get; set; } }

sealed class Settings
{
    public Dictionary<string, string>? Routes { get; set; }
    public string Bind { get; set; } = "127.0.0.1:80";
    public string[]? Allow { get; set; }
    public int MaxConnections { get; set; } = 256;
    public string? Mode { get; set; }              // proxy (default) | full (tiny local DNS + proxy)
    public DnsSettings? Dns { get; set; }
    public CacheSettings? Cache { get; set; }
    public List<ListenerSettings>? Listeners { get; set; }
}

// Tiny local DNS (used when Mode is "full"). Names are listed one by one; there are no wildcards.
sealed class DnsSettings
{
    public string? Bind { get; set; }              // loopback address:port the DNS listens on, default 127.0.0.2:53
    public string? Answer { get; set; }            // address given for every listed name, default: the address of the first http-reverse listener
    public int? Ttl { get; set; }                  // seconds, default 60
    public Dictionary<string, string>? Names { get; set; }   // name -> address ("" = the Answer address)
    public bool? FromRoutes { get; set; }          // also answer for every http-reverse route host name, default true
    public string[]? Upstream { get; set; }        // DNS servers for every other name; empty = the servers the OS uses now
}

sealed class CacheSettings
{
    public bool Enabled { get; set; } = true;
    public string? Path { get; set; }
    public int MaxBytes { get; set; } = 4 * 1024 * 1024;
    public int MinTtlSeconds { get; set; } = 3600;
    public int MaxTtlSeconds { get; set; } = 86400;
    public int StaleSeconds { get; set; } = 7 * 86400;
    public string[]? Extensions { get; set; }
}

sealed class ListenerSettings
{
    public string? Name { get; set; }
    public string? Bind { get; set; }
    public string? Mode { get; set; }              // http-reverse | http-forward | tcp
    public string[]? Allow { get; set; }           // client CIDRs, default loopback only
    public Dictionary<string, string>? Routes { get; set; }   // http-reverse: host -> upstream host[:port] (always https)
    public string? Target { get; set; }            // tcp: host:port
    public string[]? AllowHosts { get; set; }      // http-forward: destination host patterns ("example.com", "*.example.com")
    public int[]? AllowPorts { get; set; }         // http-forward: destination ports, default 80 and 443
    public bool AllowPrivate { get; set; }         // http-forward: allow private/loopback destinations (SSRF guard off)
    public string? Token { get; set; }             // http-forward: Proxy-Authorization secret (Basic password or Bearer)
    public int? MaxConnections { get; set; }
    public int? MaxBody { get; set; }
    public int? IdleSeconds { get; set; }
}

[JsonSourceGenerationOptions(ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(Root))]
partial class CfgJson : JsonSerializerContext { }

// ===== validated runtime model =====
sealed class Cidr
{
    readonly byte[] net;
    readonly int bits;
    Cidr(byte[] net, int bits) { this.net = net; this.bits = bits; }

    static IPAddress Norm(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;

    public static Cidr Parse(string s)
    {
        var p = s.Split('/');
        var ip = Norm(IPAddress.Parse(p[0].Trim()));
        int max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int bits = p.Length > 1 ? int.Parse(p[1]) : max;
        if (bits < 0 || bits > max) throw new FormatException("Bad CIDR: " + s);
        return new Cidr(ip.GetAddressBytes(), bits);
    }

    public bool Contains(IPAddress a)
    {
        var b = Norm(a).GetAddressBytes();
        if (b.Length != net.Length) return false;
        int full = bits / 8, rest = bits % 8;
        for (int i = 0; i < full; i++) if (b[i] != net[i]) return false;
        if (rest == 0) return true;
        int mask = 0xFF << (8 - rest) & 0xFF;
        return (b[full] & mask) == (net[full] & mask);
    }
}

sealed class Listener
{
    public string Name = "", Mode = "";
    public IPEndPoint Bind = null!;
    public Cidr[] Allow = [];
    public Dictionary<string, (string Host, int Port)> Routes = new();
    public string TargetHost = "";
    public int TargetPort;
    public string[] AllowHosts = [];
    public int[] AllowPorts = [80, 443];
    public bool AllowPrivate;
    public string? Token;
    public int MaxConnections = 256, MaxBody = 4096, IdleSeconds = 300;

    public bool Allows(IPAddress a) { foreach (var c in Allow) if (c.Contains(a)) return true; return false; }
    public bool PortOk(int p) => Array.IndexOf(AllowPorts, p) >= 0;

    public bool HostOk(string host)
    {
        foreach (var p in AllowHosts)
        {
            if (p == "*") return true;
            if (p.StartsWith("*.")) { if (host.EndsWith(p[1..], StringComparison.Ordinal)) return true; }
            else if (host == p) return true;
        }
        return false;
    }
}

sealed class DnsRuntime
{
    public IPEndPoint Bind = new(IPAddress.Parse("127.0.0.2"), 53);
    public int Ttl = 60;
    public Dictionary<string, IPAddress> Names = new();
    public IPEndPoint[] Upstream = [];
}

sealed class Config
{
    public Listener[] Listeners = [];
    public CacheSettings Cache = new();
    public string Mode = "proxy";
    public DnsRuntime Dns = new();

    // Set from --mode on the command line; it wins over PkiProxySettings:Mode.
    public static string? ModeOverride;

    // Host names that http-reverse listeners answer for; used by the --hosts-* switches (wildcards cannot go in a hosts file).
    public string[] HostNames() => Listeners.Where(l => l.Mode == "http-reverse").SelectMany(l => l.Routes.Keys).Concat(Dns.Names.Keys)
        .Where(h => !h.Contains('*')).Distinct().OrderBy(h => h, StringComparer.Ordinal).ToArray();

    public static Config Load(string path)
    {
        if (!File.Exists(path)) throw new InvalidOperationException("Config not found: " + path);
        var root = JsonSerializer.Deserialize(File.ReadAllText(path), CfgJson.Default.Root);
        var s = root?.PkiProxySettings ?? throw new InvalidOperationException("PkiProxySettings section is missing in " + path);

        var raw = new List<ListenerSettings>();
        if (s.Routes is { Count: > 0 })
            raw.Add(new ListenerSettings { Name = "pki", Bind = s.Bind, Mode = "http-reverse", Allow = s.Allow, Routes = s.Routes, MaxConnections = s.MaxConnections });
        if (s.Listeners != null) raw.AddRange(s.Listeners);
        if (raw.Count == 0) throw new InvalidOperationException("No listeners: add PkiProxySettings:Routes or PkiProxySettings:Listeners");

        var list = new List<Listener>();
        for (int i = 0; i < raw.Count; i++) list.Add(Make(raw[i], i));
        var dup = list.GroupBy(l => l.Bind.ToString()).FirstOrDefault(g => g.Count() > 1);
        if (dup != null) throw new InvalidOperationException("Two listeners use the same bind address: " + dup.Key);
        string mode = (ModeOverride ?? s.Mode ?? "proxy").Trim().ToLowerInvariant();
        if (mode != "proxy" && mode != "full") throw new InvalidOperationException("Mode must be proxy or full (got '" + mode + "')");
        var cfg = new Config { Listeners = list.ToArray(), Cache = s.Cache ?? new CacheSettings(), Mode = mode };
        cfg.Dns = MakeDns(s.Dns, cfg.Listeners);
        return cfg;
    }

    // ----- tiny DNS settings; always validated, only started when Mode is "full" -----
    static DnsRuntime MakeDns(DnsSettings? d, Listener[] listeners)
    {
        d ??= new DnsSettings();
        var r = new DnsRuntime();
        const string w = "Dns: ";

        if (!string.IsNullOrWhiteSpace(d.Bind))
        {
            if (!IPEndPoint.TryParse(d.Bind, out var ep)) throw new InvalidOperationException(w + "Bind must look like 127.0.0.2:53");
            r.Bind = ep.Port == 0 ? new IPEndPoint(ep.Address, 53) : ep;
        }
        // Loopback only: a resolver on a LAN address would answer anybody on the network.
        if (!IPAddress.IsLoopback(r.Bind.Address)) throw new InvalidOperationException(w + "Bind must be a loopback address (127.x.x.x or ::1), got " + r.Bind.Address);
        r.Ttl = Math.Clamp(d.Ttl ?? 60, 0, 3600);

        IPAddress answer = IPAddress.Loopback;
        var first = listeners.FirstOrDefault(l => l.Mode == "http-reverse");
        if (first != null && !first.Bind.Address.Equals(IPAddress.Any) && !first.Bind.Address.Equals(IPAddress.IPv6Any) && first.Bind.AddressFamily == AddressFamily.InterNetwork) answer = first.Bind.Address;
        if (!string.IsNullOrWhiteSpace(d.Answer))
        {
            if (!IPAddress.TryParse(d.Answer, out var a) || a.AddressFamily != AddressFamily.InterNetwork) throw new InvalidOperationException(w + "Answer must be an IPv4 address");
            answer = a;
        }

        if (d.FromRoutes ?? true)
            foreach (var l in listeners.Where(l => l.Mode == "http-reverse"))
                foreach (var host in l.Routes.Keys)
                    if (!host.Contains('*')) r.Names[CheckName(host)] = answer;

        if (d.Names != null)
            foreach (var kv in d.Names)
            {
                IPAddress ip = answer;
                if (!string.IsNullOrWhiteSpace(kv.Value))
                    if (!IPAddress.TryParse(kv.Value.Trim(), out ip!) || ip.AddressFamily != AddressFamily.InterNetwork) throw new InvalidOperationException(w + "'" + kv.Key + "' needs an IPv4 address or an empty value");
                r.Names[CheckName(kv.Key)] = ip;
            }

        if (d.Upstream is { Length: > 0 })
        {
            var ups = new List<IPEndPoint>();
            foreach (var u in d.Upstream)
            {
                if (!IPEndPoint.TryParse(u.Trim(), out var ep)) throw new InvalidOperationException(w + "Upstream '" + u + "' is not an address (use 9.9.9.9 or 9.9.9.9:53)");
                if (ep.Port == 0) ep = new IPEndPoint(ep.Address, 53);
                if (ep.Equals(r.Bind)) throw new InvalidOperationException(w + "Upstream may not be the DNS's own address");
                ups.Add(ep);
            }
            r.Upstream = ups.ToArray();
        }
        return r;
    }

    // One literal host name per entry: letters, digits, '-', at least two labels, no wildcard.
    static string CheckName(string raw)
    {
        string n = raw.Trim().ToLowerInvariant().TrimEnd('.');
        bool ok = n.Length is > 3 and <= 253 && n.Contains('.');
        if (ok)
            foreach (var label in n.Split('.'))
                if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' || !label.All(ch => ch is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-')) { ok = false; break; }
        if (!ok) throw new InvalidOperationException("Dns: '" + raw + "' is not a plain host name (wildcards are not supported; list every name)");
        return n;
    }

    static Listener Make(ListenerSettings x, int i)
    {
        var l = new Listener { Name = x.Name ?? "listener" + (i + 1), Mode = (x.Mode ?? "").ToLowerInvariant() };
        string where = "Listener '" + l.Name + "': ";
        if (!IPEndPoint.TryParse(x.Bind ?? "", out var ep)) throw new InvalidOperationException(where + "Bind must look like 127.0.0.1:80");
        l.Bind = ep;
        l.Allow = (x.Allow is { Length: > 0 } ? x.Allow : ["127.0.0.0/8", "::1/128"]).Select(Cidr.Parse).ToArray();
        l.MaxConnections = Math.Clamp(x.MaxConnections ?? 256, 1, 10000);
        l.IdleSeconds = Math.Clamp(x.IdleSeconds ?? 300, 5, 86400);
        l.Token = string.IsNullOrEmpty(x.Token) ? null : x.Token;

        switch (l.Mode)
        {
            case "http-reverse":
                if (x.Routes == null || x.Routes.Count == 0) throw new InvalidOperationException(where + "Routes is empty");
                foreach (var kv in x.Routes)
                {
                    var (h, p) = Net.Authority(kv.Value, 443);
                    l.Routes[kv.Key.Trim().ToLowerInvariant().TrimEnd('.')] = (h, p);
                }
                l.MaxBody = Math.Clamp(x.MaxBody ?? 4096, 0, 1 << 20);
                break;
            case "http-forward":
                if (x.AllowHosts == null || x.AllowHosts.Length == 0) throw new InvalidOperationException(where + "AllowHosts is required (no open proxy)");
                l.AllowHosts = x.AllowHosts.Select(h => h.Trim().ToLowerInvariant()).ToArray();
                if (x.AllowPorts is { Length: > 0 }) l.AllowPorts = x.AllowPorts;
                l.AllowPrivate = x.AllowPrivate;
                l.MaxBody = Math.Clamp(x.MaxBody ?? 65536, 0, 8 << 20);
                break;
            case "tcp":
                if (string.IsNullOrWhiteSpace(x.Target)) throw new InvalidOperationException(where + "Target (host:port) is required");
                (l.TargetHost, l.TargetPort) = Net.Authority(x.Target, 0);
                if (l.TargetPort == 0) throw new InvalidOperationException(where + "Target needs a port");
                break;
            default:
                throw new InvalidOperationException(where + "Mode must be http-reverse, http-forward or tcp");
        }
        return l;
    }
}

static class Paths
{
    public static string AppDir => Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
    public static string Config(Args a) => a.Value("config") ?? Path.Combine(AppDir, "appsettings.json");
}
