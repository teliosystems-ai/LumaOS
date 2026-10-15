using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows
{
    // Explicit unsigned input, not a saved enrollment, Linux principal or grant.
    public sealed class IngestionEnrollment
    {
        public string EnrollmentId;
        public string WindowsSid;
        public string Root;
        public string RelativePath;
        public int MaximumBytes;
        public string ExpectedSha256;
    }

    public sealed class IngestionResult
    {
        public string WindowsSid;
        public string EnrollmentId;
        public string ReviewSha256;
        public string Root;
        public string RelativePath;
        public string Sha256;
        public long Bytes;
        public uint VolumeSerial;
        public string FileId;
        public string ContentHex;
        public bool ReadOnly = true;
        public bool InputAuthenticated = false;
        public bool ProductGrants = false;
        public bool AuthenticatedLinuxBridge = false;
        public bool ConfidentialityEstablished = false;
        public bool ProductionQualified = false;
        public bool GateClosing = false;
        public bool PartialDeliveryPossible = true;
        public bool HardDeadlineEnforced = false;
        public bool OpenNoRecallRequested = true;
        public bool CloudProviderQualified = false;
    }

    public static class ScopedIngestion
    {
        public const int MaximumBytes = 1048576;
        public const int MaximumEnrollmentBytes = 8192;
        public const uint OpenNoRecall = 0x00100000;
        public const uint OpenReparsePoint = 0x00200000;
        private const uint ReadAccess = 0x00020081; // Data/list + attributes + READ_CONTROL.
        private const uint InvalidAttributes = 0x00400000 | 0x00100000 | 0x00080000 | 0x00040000 | 0x1000 | 0x400;
        private const int MaximumComponents = 32;
        private const int DeadlineMilliseconds = 5000;

        [StructLayout(LayoutKind.Sequential)]
        private struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)]
        private struct Statistics {
            public Luid TokenId, AuthenticationId;
            public long Expiration;
            public uint TokenType, ImpersonationLevel, DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
            public Luid ModifiedId;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Mapping { public uint Read, Write, Execute, All; }

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, StringBuilder volumeName, uint volumeLength, out uint serial, out uint maximumComponent, out uint flags, StringBuilder filesystem, uint filesystemLength);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
        private static extern uint GetDriveType(string root);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr value);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool CancelIoEx(SafeFileHandle file, IntPtr overlapped);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr information, uint length, out uint returned);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern uint GetSecurityInfo(SafeFileHandle file, uint kind, uint requested, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool AccessCheck(IntPtr descriptor, IntPtr token, uint requested, ref Mapping mapping, IntPtr privileges, ref uint privilegeLength, out uint granted, out bool allowed);

        private sealed class Token : IDisposable
        {
            public readonly IntPtr Primary;
            public readonly IntPtr AccessToken;
            public readonly string Sid;
            private readonly Statistics initial;

            public Token()
            {
                IntPtr primary = IntPtr.Zero, duplicate = IntPtr.Zero;
                try {
                    NoImpersonation();
                    if (!OpenProcessToken(GetCurrentProcess(), 0x000a, out primary)) throw Failure("Cannot inspect the actual process token.");
                    ValidateToken(primary);
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                        Sid = identity.User.Value;
                        bool interactive = false;
                        foreach (IdentityReference group in identity.Groups) if (group.Value == "S-1-5-4") interactive = true;
                        if (!interactive || Sid == "S-1-5-18" || Sid == "S-1-5-19" || Sid == "S-1-5-20" || Sid.StartsWith("S-1-5-80-", StringComparison.Ordinal))
                            throw new SecurityException("An actual nonservice interactive Windows SID is required.");
                    }
                    initial = ReadStatistics(primary);
                    if (!DuplicateToken(primary, 2, out duplicate)) throw Failure("Cannot construct an ordinary-caller ACL check token.");
                    Primary = primary; AccessToken = duplicate;
                } catch {
                    if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
                    if (primary != IntPtr.Zero) CloseHandle(primary);
                    throw;
                }
            }
            private static void NoImpersonation()
            {
                IntPtr thread;
                if (OpenThreadToken(GetCurrentThread(), 8, true, out thread)) {
                    CloseHandle(thread);
                    throw new SecurityException("Active impersonation is forbidden for file ingestion.");
                }
                if (Marshal.GetLastWin32Error() != 1008) throw Failure("Cannot verify the thread token.");
            }
            private static IntPtr Information(IntPtr token, int kind, int maximum)
            {
                uint length;
                GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
                if (length == 0 || length > maximum) throw new SecurityException("Token information exceeds its bound.");
                IntPtr buffer = Marshal.AllocHGlobal((int)length);
                if (!GetTokenInformation(token, kind, buffer, length, out length)) {
                    Marshal.FreeHGlobal(buffer); throw Failure("Cannot inspect token information.");
                }
                return buffer;
            }
            private static Statistics ReadStatistics(IntPtr token)
            {
                IntPtr buffer = Information(token, 10, 256);
                try { return (Statistics)Marshal.PtrToStructure(buffer, typeof(Statistics)); }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            private static void ValidateToken(IntPtr token)
            {
                IntPtr elevation = Information(token, 20, 16);
                try { if (Marshal.ReadInt32(elevation) != 0) throw new SecurityException("Elevated tokens are forbidden; use the ordinary interactive caller."); }
                finally { Marshal.FreeHGlobal(elevation); }
                if (ReadStatistics(token).TokenType != 1) throw new SecurityException("The process must use a primary token.");
                IntPtr privileges = Information(token, 3, 8192);
                try {
                    uint count = (uint)Marshal.ReadInt32(privileges);
                    if (count > 128) throw new SecurityException("Token privilege count exceeds its bound.");
                    foreach (string name in new string[] { "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege" }) {
                        Luid blocked;
                        if (!LookupPrivilegeValue(null, name, out blocked)) throw Failure("Cannot identify a prohibited privilege.");
                        for (uint index = 0; index < count; index++) {
                            IntPtr entry = IntPtr.Add(privileges, checked(4 + (int)index * 12));
                            if ((uint)Marshal.ReadInt32(entry) == blocked.Low && Marshal.ReadInt32(entry, 4) == blocked.High && ((uint)Marshal.ReadInt32(entry, 8) & 2) != 0)
                                throw new SecurityException("Enabled debug/backup/restore/ownership privileges are forbidden.");
                        }
                    }
                } finally { Marshal.FreeHGlobal(privileges); }
            }
            public void Check()
            {
                NoImpersonation();
                IntPtr actual;
                if (!OpenProcessToken(GetCurrentProcess(), 8, out actual)) throw Failure("Cannot recheck the current process token.");
                try {
                    ValidateToken(actual);
                    Statistics current = ReadStatistics(actual);
                    if (!Same(initial.TokenId, current.TokenId) || !Same(initial.AuthenticationId, current.AuthenticationId) || !Same(initial.ModifiedId, current.ModifiedId))
                        throw new SecurityException("The actual caller token changed during ingestion.");
                } finally { CloseHandle(actual); }
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) if (identity.User.Value != Sid) throw new SecurityException("The current Windows SID changed.");
            }
            private static bool Same(Luid a, Luid b) { return a.Low == b.Low && a.High == b.High; }
            public void Dispose() { CloseHandle(AccessToken); CloseHandle(Primary); }
        }

        private sealed class Lease : IDisposable
        {
            public readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
            public readonly List<string> Paths = new List<string>();
            public readonly List<FileInformation> Identities = new List<FileInformation>();
            public SafeFileHandle File { get { return Handles[Handles.Count - 1]; } }
            public void Add(string path, bool directory, Token token)
            {
                // Query attributes and caller ACL before asking for data/list
                // access. Attribute-only handles do not arbitrate Windows
                // sharing, so compare the subsequently pinned identity too.
                // OPEN_NO_RECALL is requested, not a claim of universal cloud
                // filter behavior; provider-specific qualification is absent.
                FileInformation metadata;
                using (SafeFileHandle attributes = CreateFile(path, 0x00020080, 1, IntPtr.Zero, 3,
                    OpenReparsePoint | OpenNoRecall | (directory ? 0x02000000U : 0), IntPtr.Zero)) {
                    if (attributes.IsInvalid) throw Failure("Cannot inspect the explicit no-recall source attributes.");
                    metadata = Observe(attributes, path, directory);
                    Acl(attributes, token);
                    SafeFileHandle handle = CreateFile(path, ReadAccess, 1, IntPtr.Zero, 3,
                        OpenReparsePoint | OpenNoRecall | (directory ? 0x02000000U : 0x40000000U), IntPtr.Zero);
                    if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "Cannot pin the explicit ordinary-caller source path."); }
                    try {
                        FileInformation information = Observe(handle, path, directory);
                        if (!Same(metadata, information)) throw new IOException("The source changed between no-recall attribute inspection and data-handle pinning.");
                        Acl(handle, token);
                        Handles.Add(handle); Paths.Add(path); Identities.Add(information);
                    } catch { handle.Dispose(); throw; }
                }
            }
            public void Check(Token token, Stopwatch clock)
            {
                Deadline(clock); token.Check();
                for (int index = 0; index < Handles.Count; index++) {
                    FileInformation now = Observe(Handles[index], Paths[index], index != Handles.Count - 1);
                    if (!Same(Identities[index], now)) throw new IOException("Pinned source identity, attributes, size or write time changed.");
                    Acl(Handles[index], token);
                    Deadline(clock);
                }
            }
            public void Dispose() { for (int index = Handles.Count - 1; index >= 0; index--) Handles[index].Dispose(); }
        }

        private static Exception Failure(string message) { return new Win32Exception(Marshal.GetLastWin32Error(), message); }
        private static void Deadline(Stopwatch clock) { if (clock.ElapsedMilliseconds >= DeadlineMilliseconds) throw new TimeoutException("The bounded ingestion observation deadline expired."); }
        private static bool Same(FileInformation a, FileInformation b)
        {
            // Ancestor directory write times are intentionally part of this
            // stable observation: even unrelated concurrent namespace changes
            // can conservatively refuse; there is no automatic read retry.
            return a.Attributes == b.Attributes && a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow && a.Links == b.Links &&
                a.SizeHigh == b.SizeHigh && a.SizeLow == b.SizeLow && a.Creation.dwHighDateTime == b.Creation.dwHighDateTime && a.Creation.dwLowDateTime == b.Creation.dwLowDateTime &&
                a.Write.dwHighDateTime == b.Write.dwHighDateTime && a.Write.dwLowDateTime == b.Write.dwLowDateTime;
        }
        private static FileInformation Observe(SafeFileHandle handle, string expected, bool directory)
        {
            FileInformation info;
            if (!GetFileInformationByHandle(handle, out info)) throw Failure("Cannot observe source identity.");
            if ((info.Attributes & InvalidAttributes) != 0 || (((info.Attributes & 0x10) != 0) != directory) || (!directory && info.Links != 1))
                throw new IOException("Reparse, placeholder, offline, hard-linked or wrong-type sources are forbidden.");
            StringBuilder final = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
            if (length == 0 || length >= final.Capacity || !final.ToString().StartsWith("\\\\?\\", StringComparison.Ordinal) ||
                !String.Equals(final.ToString().Substring(4).TrimEnd('\\'), expected.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException("The opened source differs from its canonical local path.");
            StringBuilder fs = new StringBuilder(32), name = new StringBuilder(256);
            uint serial, maximum, flags;
            if (!GetVolumeInformationByHandleW(handle, name, (uint)name.Capacity, out serial, out maximum, out flags, fs, (uint)fs.Capacity) || fs.ToString() != "NTFS" || serial != info.Volume)
                throw new IOException("Scoped source ingestion requires local NTFS handles.");
            return info;
        }
        private static void Acl(SafeFileHandle handle, Token token)
        {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint result = GetSecurityInfo(handle, 1, 7, out owner, out group, out dacl, out sacl, out descriptor);
            if (result != 0) throw new Win32Exception((int)result, "Cannot inspect the source ACL at use.");
            try {
                if (dacl == IntPtr.Zero) throw new SecurityException("An unconstrained NULL DACL is not a scoped source.");
                Mapping mapping = new Mapping { Read = 0x120089, Write = 0x120116, Execute = 0x1200a0, All = 0x1f01ff };
                uint privilegesLength = 8192, granted; bool allowed;
                IntPtr privileges = Marshal.AllocHGlobal((int)privilegesLength);
                try {
                    if (!AccessCheck(descriptor, token.AccessToken, ReadAccess, ref mapping, privileges, ref privilegesLength, out granted, out allowed)) throw Failure("Cannot perform the actual caller ACL check.");
                    if (!allowed || (granted & ReadAccess) != ReadAccess) throw new UnauthorizedAccessException("The current ordinary-caller ACL denies this exact read.");
                } finally { Marshal.FreeHGlobal(privileges); }
            } finally { LocalFree(descriptor); }
        }

        private static void Component(string component)
        {
            if (component.Length == 0 || component.Length > 255 || component == "." || component == ".." || component.EndsWith(".", StringComparison.Ordinal) || component.EndsWith(" ", StringComparison.Ordinal) ||
                component.IndexOfAny(new char[] { ':', '/', '\\', '*', '?', '"', '<', '>', '|', '~' }) >= 0 || !component.IsNormalized(NormalizationForm.FormC))
                throw new ArgumentException("Source names require canonical nontraversing local components.");
            foreach (char c in component) if (Char.IsControl(c)) throw new ArgumentException("Source path control characters are forbidden.");
            string stem = component.Split('.')[0].ToUpperInvariant();
            if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" || stem == "CLOCK$" ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && ((stem[3] >= '0' && stem[3] <= '9') || stem[3] == '\u00b9' || stem[3] == '\u00b2' || stem[3] == '\u00b3')))
                throw new ArgumentException("DOS device aliases are forbidden.");
        }
        public static string ValidateRoot(string root)
        {
            if (String.IsNullOrEmpty(root) || root.Length > 220 || root.Length < 4 || !((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z')) || root[1] != ':' || root[2] != '\\' || root.EndsWith("\\", StringComparison.Ordinal) || root.IndexOf('/') >= 0 ||
                !String.Equals(Path.GetFullPath(root), root, StringComparison.Ordinal)) throw new ArgumentException("Enrollment requires an exact canonical absolute local directory, not a drive root.");
            string[] components = root.Substring(3).Split('\\');
            if (components.Length > MaximumComponents) throw new ArgumentException("Source ancestor count exceeds its bound.");
            foreach (string component in components) Component(component);
            uint type = GetDriveType(root.Substring(0, 3));
            if (type != 2 && type != 3) throw new ArgumentException("Network, unknown and nonlocal source drives are forbidden.");
            return root;
        }
        private static string[] Relative(string relative)
        {
            if (String.IsNullOrEmpty(relative) || relative.Length > 220 || Path.IsPathRooted(relative)) throw new ArgumentException("An exact nonrooted relative file is required.");
            string[] components = relative.Split('\\');
            if (components.Length > MaximumComponents) throw new ArgumentException("Relative source depth exceeds its bound.");
            foreach (string component in components) Component(component);
            return components;
        }
        private static void Validate(IngestionEnrollment enrollment)
        {
            if (enrollment == null || enrollment.MaximumBytes < 1 || enrollment.MaximumBytes > MaximumBytes ||
                !System.Text.RegularExpressions.Regex.IsMatch(enrollment.EnrollmentId ?? "", "\\A[a-f0-9]{32}\\z") ||
                !System.Text.RegularExpressions.Regex.IsMatch(enrollment.ExpectedSha256 ?? "", "\\A[a-f0-9]{64}\\z")) throw new ArgumentException("Enrollment requires exact bounded identity, size and SHA256.");
            SecurityIdentifier sid = new SecurityIdentifier(enrollment.WindowsSid);
            if (sid.Value != enrollment.WindowsSid) throw new ArgumentException("Enrollment SID is not canonical.");
            ValidateRoot(enrollment.Root); Relative(enrollment.RelativePath);
            CompleteDepth(enrollment.Root, enrollment.RelativePath);
            if (enrollment.Root.Length + enrollment.RelativePath.Length + 1 > 240) throw new ArgumentException("The exact source path exceeds its fixed bound.");
        }
        private static string Hex(byte[] bytes) { StringBuilder output = new StringBuilder(bytes.Length * 2); foreach (byte b in bytes) output.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)); return output.ToString(); }
        private static string Hash(byte[] bytes) { using (SHA256 sha = SHA256.Create()) return Hex(sha.ComputeHash(bytes)); }
        public static string Review(IngestionEnrollment enrollment)
        {
            Validate(enrollment);
            string value = "luma-windows-explicit-read-v1\n" + enrollment.EnrollmentId + "\n" + enrollment.WindowsSid + "\n" + enrollment.Root + "\n" + enrollment.RelativePath + "\n" + enrollment.MaximumBytes.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n" + enrollment.ExpectedSha256 + "\n";
            return Hash(new UTF8Encoding(false, true).GetBytes(value));
        }
        public static string CurrentSid() { using (Token token = new Token()) return token.Sid; }

        private static void CompleteDepth(string root, string relative)
        {
            if (root.Substring(3).Split('\\').Length + relative.Split('\\').Length > MaximumComponents)
                throw new ArgumentException("The complete root/relative source depth exceeds its fixed handle bound.");
        }

        private static Lease Pin(string root, string relativePath, Token token, Stopwatch clock)
        {
            CompleteDepth(root, relativePath);
            Lease lease = new Lease();
            try {
                string path = root.Substring(0, 3);
                lease.Add(path, true, token);
                foreach (string component in root.Substring(3).Split('\\')) { Deadline(clock); path = Path.Combine(path, component); lease.Add(path, true, token); }
                string[] relative = Relative(relativePath);
                for (int index = 0; index < relative.Length; index++) { Deadline(clock); path = Path.Combine(path, relative[index]); lease.Add(path, index != relative.Length - 1, token); }
                if (lease.Handles.Count > MaximumComponents + 1) throw new IOException("The complete enrolled path exceeds its handle bound.");
                lease.Check(token, clock);
                return lease;
            } catch { lease.Dispose(); throw; }
        }

        // Even unsigned control input is opened as the ordinary interactive
        // caller through the same pinned, no-follow, no-hydration handle chain.
        // It is inert data and has no expected content digest until reviewed.
        public static byte[] CaptureEnrollmentFile(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentException("An explicit local enrollment file is required.");
            string root = Path.GetDirectoryName(path), relative = Path.GetFileName(path);
            ValidateRoot(root); Relative(relative);
            CompleteDepth(root, relative);
            if (!String.Equals(Path.Combine(root, relative), path, StringComparison.Ordinal) || path.Length > 240) throw new ArgumentException("Enrollment input requires its canonical exact local file path.");
            Stopwatch clock = Stopwatch.StartNew();
            using (Token token = new Token())
            using (Lease lease = Pin(root, relative, token, clock)) {
                FileInformation file = lease.Identities[lease.Identities.Count - 1];
                long length = ((long)file.SizeHigh << 32) | file.SizeLow;
                if (length < 1 || length > MaximumEnrollmentBytes) throw new IOException("Enrollment input exceeds its fixed 8192-byte bound.");
                using (FileStream stream = new FileStream(lease.File, FileAccess.Read, 32768, true)) {
                    byte[] bytes = Read(stream, lease, token, clock, (int)length);
                    stream.Position = 0;
                    byte[] repeated = Read(stream, lease, token, clock, (int)length);
                    if (Hash(bytes) != Hash(repeated)) throw new IOException("Enrollment input changed during bounded capture.");
                    lease.Check(token, clock);
                    return bytes;
                }
            }
        }

        private static byte[] Read(FileStream stream, Lease lease, Token token, Stopwatch clock, int length)
        {
            byte[] bytes = new byte[length]; int offset = 0;
            while (offset < length) {
                lease.Check(token, clock);
                int count = Math.Min(32768, length - offset);
                using (CancellationTokenSource cancellation = new CancellationTokenSource()) {
                    int remaining = DeadlineMilliseconds - checked((int)clock.ElapsedMilliseconds);
                    if (remaining <= 0) throw new TimeoutException("The bounded source read deadline expired.");
                    cancellation.CancelAfter(remaining);
                    System.Threading.Tasks.Task<int> pending = stream.ReadAsync(bytes, offset, count, cancellation.Token);
                    if (!pending.Wait(remaining)) { CancelIoEx(lease.File, IntPtr.Zero); throw new TimeoutException("The source read observation window expired."); }
                    int read = pending.GetAwaiter().GetResult();
                    if (read == 0) throw new EndOfStreamException("The source shortened during its bounded read.");
                    offset += read;
                }
            }
            lease.Check(token, clock);
            return bytes;
        }

        public static IngestionResult Inspect(IngestionEnrollment enrollment, string confirmation)
        {
            if (enrollment == null) throw new ArgumentNullException("enrollment");
            // The caller can retain and mutate its public data object. Keep a
            // private immutable-in-use snapshot before validating confirmation.
            enrollment = new IngestionEnrollment { EnrollmentId = enrollment.EnrollmentId, WindowsSid = enrollment.WindowsSid,
                Root = enrollment.Root, RelativePath = enrollment.RelativePath, MaximumBytes = enrollment.MaximumBytes, ExpectedSha256 = enrollment.ExpectedSha256 };
            string review = Review(enrollment);
            if (confirmation != "read-exact-file:" + review) throw new SecurityException("Operator confirmation does not bind this exact SID, scope, limit and expected content.");
            Stopwatch clock = Stopwatch.StartNew();
            using (Token token = new Token()) {
                if (token.Sid != enrollment.WindowsSid) throw new SecurityException("Enrollment belongs to a different actual Windows caller SID.");
                // The window is checked between local operations and cancels
                // asynchronous reads. Kernel metadata operations and disposal
                // can block in storage/filter drivers; this is not a process-
                // supervised hard deadline or a product authorization session.
                using (Lease lease = Pin(enrollment.Root, enrollment.RelativePath, token, clock)) {
                    FileInformation file = lease.Identities[lease.Identities.Count - 1];
                    long length = ((long)file.SizeHigh << 32) | file.SizeLow;
                    if (length < 0 || length > enrollment.MaximumBytes) throw new IOException("The exact source exceeds its reviewed byte limit.");
                    byte[] bytes;
                    using (FileStream stream = new FileStream(lease.File, FileAccess.Read, 32768, true)) {
                        bytes = Read(stream, lease, token, clock, (int)length);
                        if (Hash(bytes) != enrollment.ExpectedSha256) throw new SecurityException("Source bytes differ from the operator-reviewed SHA256.");
                        stream.Position = 0;
                        byte[] repeated = Read(stream, lease, token, clock, (int)length);
                        if (Hash(repeated) != enrollment.ExpectedSha256) throw new SecurityException("Source bytes changed during repeated observation.");
                        lease.Check(token, clock);
                    }
                    // Only verified complete bytes leave the reader. A process
                    // dying during its caller's stdout serialization can still
                    // deliver a prefix; this is not a product export session.
                    return new IngestionResult { WindowsSid = token.Sid, EnrollmentId = enrollment.EnrollmentId, ReviewSha256 = review,
                        Root = enrollment.Root, RelativePath = enrollment.RelativePath, Sha256 = enrollment.ExpectedSha256, Bytes = length,
                        VolumeSerial = file.Volume, FileId = file.IndexHigh.ToString("x8") + file.IndexLow.ToString("x8"), ContentHex = Hex(bytes) };
                }
            }
        }
    }
}
