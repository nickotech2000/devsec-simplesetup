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
    public CacheSettings? Cache { get; set; }
    public List<ListenerSettings>? Listeners { get; set; }
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

sealed class Config
{
    public Listener[] Listeners = [];
    public CacheSettings Cache = new();

    // Host names that http-reverse listeners answer for; used by the --hosts-* switches (wildcards cannot go in a hosts file).
    public string[] HostNames() => Listeners.Where(l => l.Mode == "http-reverse").SelectMany(l => l.Routes.Keys)
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
        return new Config { Listeners = list.ToArray(), Cache = s.Cache ?? new CacheSettings() };
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
