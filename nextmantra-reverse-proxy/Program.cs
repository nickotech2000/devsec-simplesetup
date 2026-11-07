/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

class PkiProxy
{
    private static Dictionary<string, string> routes = new Dictionary<string, string>();
    private static CancellationTokenSource cts = new CancellationTokenSource();
    private static TcpListener? listener;

    static async Task Main()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("-------------------------------------------------");
        Console.WriteLine("Author  : Nicko Satria Utama");
        Console.WriteLine("Company : Agantra Inovatif OU");
        Console.WriteLine("Email   : nicko@nextmantra.com");
        Console.WriteLine("-------------------------------------------------");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("--- NextMantra Native .NET 10 Sockets Proxy ---");
        Console.ResetColor();
        
        try
        {
            if (!File.Exists("appsettings.json"))
            {
                Console.WriteLine("FATAL ERROR: appsettings.json not found next to the executable!");
                return;
            }

            string json = File.ReadAllText("appsettings.json");
            string[] lines = json.Split(new[] { ',', '{', '}', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            char[] trimChars = new[] { ' ', '"', '\t' };

            foreach (var line in lines)
            {
                if (line.Contains(":"))
                {
                    string[] parts = line.Split(':');
                    string key = parts[0].Trim(trimChars);
                    string val = parts[1].Trim(trimChars);
                    if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(val))
                    {
                        routes[key.ToLower()] = val.ToLower();
                        Console.WriteLine("Loaded Map: http://" + key + " ---> https://" + val);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error parsing configuration: " + ex.Message);
            return;
        }

        if (routes.Count == 0)
        {
            Console.WriteLine("No operational domain pathways loaded.");
            return;
        }

        listener = new TcpListener(IPAddress.Loopback, 80);
        
        // Linux/macOS address reuse enablement to avoid port collisions
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

        try
        {
            listener.Start();
            Console.WriteLine("\nProxy active and listening on local http://127.0.0.1:80...");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(">> PRESS [ENTER] TWICE TO TURN OFF THE PROXY <<\n");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.WriteLine("START FAILURE: Make sure you run with elevated privileges (Sudo/Administrator)! (Error: " + ex.Message + ")");
            return;
        }

        Task listenTask = Task.Run(() => StartListeningAsync(cts.Token));

        Console.ReadLine();
        Console.ReadLine();

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Shutting down proxy infrastructure cleanly...");
        Console.ResetColor();

        cts.Cancel();
        listener.Stop();

        await Task.WhenAny(listenTask, Task.Delay(1000));
        Console.WriteLine("Proxy is now completely turned off.");
    }

    private static async Task StartListeningAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                TcpClient incomingClient = await listener!.AcceptTcpClientAsync(token);
                _ = Task.Run(() => HandleClientAsync(incomingClient), token);
            }
            catch (Exception) when (token.IsCancellationRequested)
            {
                break;
            }
            catch { }
        }
    }

    private static async Task HandleClientAsync(TcpClient client)
    {
        using (client)
        using (NetworkStream clientStream = client.GetStream())
        {
            byte[] buffer = new byte[8192];
            int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length);
            if (bytesRead == 0) return;

            string requestString = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            string[] requestLines = requestString.Split(new[] { "\r\n" }, StringSplitOptions.None);
            
            if (requestLines.Length == 0) return;

            string firstLine = requestLines[0];
            string[] httpParts = firstLine.Split(' ');
            string httpMethod = httpParts.Length > 0 ? httpParts[0] : "UNKNOWN";
            string requestPath = httpParts.Length > 1 ? httpParts[1] : "/";

            string hostHeader = "";
            foreach (string line in requestLines)
            {
                if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                {
                    hostHeader = line.Substring(5).Trim().ToLower();
                    break;
                }
            }

            if (string.IsNullOrEmpty(hostHeader) || !routes.TryGetValue(hostHeader, out string? targetDomain))
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine("[" + DateTime.Now.ToString("HH:mm:ss") + "] Rejected Host: " + hostHeader + " (" + httpMethod + " " + requestPath + ")");
                Console.ResetColor();

                byte[] errorResponse = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 26\r\n\r\n[PKI Proxy] Route Not Found");
                await clientStream.WriteAsync(errorResponse, 0, errorResponse.Length);
                return;
            }

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("[" + DateTime.Now.ToString("HH:mm:ss") + "] Intercepted ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(httpMethod + " ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("http://" + hostHeader + requestPath + " ---> https://" + targetDomain + requestPath);
            
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("--- BEGIN RAW INCOMING REQUEST ---");
            Console.Write(requestString);
            Console.WriteLine("\n--- END RAW INCOMING REQUEST ---\n");
            Console.ResetColor();

            try
            {
                using (TcpClient netlifyClient = new TcpClient())
                {
                    await netlifyClient.ConnectAsync(targetDomain, 443);
                    using (System.Net.Security.SslStream netlifyStream = new System.Net.Security.SslStream(netlifyClient.GetStream(), false))
                    {
                        await netlifyStream.AuthenticateAsClientAsync(targetDomain);

                        string modifiedRequest = requestString.Replace(hostHeader, targetDomain);
                        byte[] modifiedBuffer = Encoding.ASCII.GetBytes(modifiedRequest);

                        await netlifyStream.WriteAsync(modifiedBuffer, 0, modifiedBuffer.Length);

                        Task clientToNetlify = clientStream.CopyToAsync(netlifyStream);
                        Task netlifyToClient = netlifyStream.CopyToAsync(clientStream);

                        await Task.WhenAny(clientToNetlify, netlifyToClient);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[" + DateTime.Now.ToString("HH:mm:ss") + "] Netlify Pipeline Error: " + ex.Message);
                Console.ResetColor();
            }
        }
    }
}
