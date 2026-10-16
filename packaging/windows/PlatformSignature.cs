using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Luma.Windows
{
    // This public-key primitive establishes no key custody or product authority.
    public static class PlatformSignature
    {
        public const string Algorithm = "ecdsa-p256-sha256-p1363";
        private static readonly byte[] Order = Hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 32);
        [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr algorithm, string name, string provider, uint flags);
        [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
        private static extern int BCryptImportKeyPair(IntPtr algorithm, IntPtr import, string kind,
            out IntPtr key, byte[] input, uint bytes, uint flags);
        [DllImport("bcrypt.dll")]
        private static extern int BCryptVerifySignature(IntPtr key, IntPtr padding, byte[] hash,
            uint hashBytes, byte[] signature, uint signatureBytes, uint flags);
        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm, uint flags);

        private static void Success(int status, string operation)
        {
            if (status != 0) throw new CryptographicException(operation + " failed: 0x" + ((uint)status).ToString("x8"));
        }
        public static byte[] Hex(string value, int bytes)
        {
            if (bytes < 1 || bytes > 4096 || value == null || value.Length != bytes*2 ||
                !Regex.IsMatch(value, "\\A[0-9a-f]+\\z")) throw new InvalidDataException("Canonical lowercase fixed-length hexadecimal is required.");
            byte[] result = new byte[bytes];
            for (int i=0; i<bytes; i++) result[i] = Convert.ToByte(value.Substring(i*2, 2), 16);
            return result;
        }
        public static string Hash(byte[] value)
        {
            if (value == null || value.Length > 65536) throw new InvalidDataException("Hash input exceeds the fixed public-input bound.");
            using (SHA256 hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(value)).Replace("-", "").ToLowerInvariant();
        }
        public static byte[] SigningInput(byte[] statement)
        {
            if (statement == null || statement.Length < 1 || statement.Length > 4096)
                throw new InvalidDataException("Statement is outside its fixed bound.");
            byte[] prefix = Encoding.ASCII.GetBytes("luma-windows-platform-signature-v2\nlab\namd64\nW\n" + Algorithm + "\n");
            byte[] result = new byte[prefix.Length + statement.Length];
            Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
            Buffer.BlockCopy(statement, 0, result, prefix.Length, statement.Length);
            return result;
        }
        private static bool Scalar(byte[] value, int offset)
        {
            bool nonzero = false;
            for (int i=0; i<32; i++) nonzero |= value[offset+i] != 0;
            if (!nonzero) return false;
            for (int i=0; i<32; i++) {
                if (value[offset+i] < Order[i]) return true;
                if (value[offset+i] > Order[i]) return false;
            }
            return false;
        }
        public static bool Verify(byte[] publicBlob, byte[] preimage, byte[] signature)
        {
            if (publicBlob == null || publicBlob.Length != 72 || preimage == null ||
                preimage.Length < 1 || preimage.Length > 8192 || signature == null || signature.Length != 64)
                throw new InvalidDataException("Requires exact P256 ECCPUBLICBLOB, bounded preimage and 64-byte P1363 signature.");
            byte[] blob = (byte[])publicBlob.Clone();
            byte[] signed = (byte[])signature.Clone();
            byte[] input = (byte[])preimage.Clone();
            byte[] header = new byte[] {0x45,0x43,0x53,0x31,0x20,0,0,0};
            for (int i=0; i<header.Length; i++) if (blob[i] != header[i])
                throw new InvalidDataException("Only the explicit ECDSA P256 CNG ECCPUBLICBLOB format is accepted.");
            if (!Scalar(signed, 0) || !Scalar(signed, 32)) return false;
            IntPtr algorithm = IntPtr.Zero, key = IntPtr.Zero;
            try {
                Success(BCryptOpenAlgorithmProvider(out algorithm, "ECDSA_P256", "Microsoft Primitive Provider", 0), "Open fixed Microsoft ECDSA provider");
                Success(BCryptImportKeyPair(algorithm, IntPtr.Zero, "ECCPUBLICBLOB", out key, blob, 72, 0), "Import exact public key");
                byte[] digest;
                using (SHA256 hash = SHA256.Create()) digest = hash.ComputeHash(input);
                int status = BCryptVerifySignature(key, IntPtr.Zero, digest, 32, signed, 64, 0);
                if ((uint)status == 0xc000a000U) return false;
                Success(status, "Verify fixed ECDSA signature");
                return true;
            } finally {
                if (key != IntPtr.Zero) BCryptDestroyKey(key);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }
    }

    // Public inputs only. This is stable capture, not a custody directory or a
    // universal no-hydration/hard-kernel-deadline qualification.
    public sealed class PlatformInputLease : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Information
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out Information information);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern uint GetFileType(SafeFileHandle file);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        private readonly List<Information> initial = new List<Information>();
        private readonly List<bool> directories = new List<bool>();
        private FileStream stream;

        private static Information Inspect(SafeFileHandle file, bool directory)
        {
            Information value;
            if (GetFileType(file) != 1 || !GetFileInformationByHandle(file, out value))
                throw new IOException("Public inputs must be actual local disk file objects.");
            if (((value.Attributes & 0x10U) != 0) != directory ||
                (value.Attributes & (0x400U | 0x1000U | 0x40000U | 0x400000U)) != 0 ||
                (!directory && value.Links != 1))
                throw new InvalidDataException("Public input is a link, wrong type, offline file or observed cloud placeholder.");
            return value;
        }
        private static bool Same(Information a, Information b)
        {
            return a.Attributes == b.Attributes && a.Volume == b.Volume && a.Links == b.Links &&
                a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow && a.SizeHigh == b.SizeHigh && a.SizeLow == b.SizeLow &&
                a.Creation.dwHighDateTime == b.Creation.dwHighDateTime && a.Creation.dwLowDateTime == b.Creation.dwLowDateTime &&
                a.Write.dwHighDateTime == b.Write.dwHighDateTime && a.Write.dwLowDateTime == b.Write.dwLowDateTime;
        }
        public static string ValidatePath(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > 240 || !Regex.IsMatch(path, "\\A[A-Za-z]:\\\\") ||
                path.IndexOf('/') >= 0 || path.IndexOf(':', 2) >= 0 ||
                !String.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Public input requires a bounded canonical absolute local Windows path.");
            foreach (string part in path.Substring(3).Split('\\')) {
                if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" ") ||
                    part.IndexOf('~') >= 0 || !Regex.IsMatch(part, "\\A[A-Za-z0-9_. -]+\\z") ||
                    Regex.IsMatch(part, "\\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\.|\\z)", RegexOptions.IgnoreCase))
                    throw new InvalidDataException("Public input path has unsupported or ambiguous components.");
            }
            DriveType kind = new DriveInfo(Path.GetPathRoot(path)).DriveType;
            if (kind != DriveType.Fixed && kind != DriveType.Removable)
                throw new InvalidDataException("Public input storage must be a local fixed or removable drive.");
            return path;
        }
        private SafeFileHandle Open(string path, bool directory, uint access)
        {
            SafeFileHandle file = CreateFile(path, access, 1, IntPtr.Zero, 3,
                directory ? 0x02300000U : 0x08300000U, IntPtr.Zero);
            if (file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(error); }
            try {
                Information metadata = Inspect(file, directory);
                StringBuilder final = new StringBuilder(512);
                uint count = GetFinalPathNameByHandle(file, final, (uint)final.Capacity, 0);
                if (count == 0 || count >= final.Capacity ||
                    !String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Public input final path differs from its selected object.");
                handles.Add(file); initial.Add(metadata); directories.Add(directory);
                return file;
            } catch { file.Dispose(); throw; }
        }
        public static PlatformInputLease Acquire(string path)
        {
            ValidatePath(path);
            PlatformInputLease lease = new PlatformInputLease();
            try {
                string current = path.Substring(0,3);
                lease.Open(current, true, 0x80);
                string[] pieces = path.Substring(3).Split('\\');
                if (pieces.Length > 32) throw new InvalidDataException("Public input path exceeds its handle bound.");
                for (int i=0; i<pieces.Length-1; i++) {
                    current = Path.Combine(current, pieces[i]);
                    lease.Open(current, true, 0x80);
                }
                SafeFileHandle metadata = lease.Open(path, false, 0x80);
                SafeFileHandle data = lease.Open(path, false, 0x80000000);
                if (!Same(Inspect(metadata, false), Inspect(data, false)))
                    throw new InvalidDataException("Metadata and data opens selected different public input objects.");
                // FileStream owns this final data handle; the lease retains all
                // metadata/ancestor handles independently until disposal.
                lease.handles.RemoveAt(lease.handles.Count-1);
                lease.initial.RemoveAt(lease.initial.Count-1);
                lease.directories.RemoveAt(lease.directories.Count-1);
                try { lease.stream = new FileStream(data, FileAccess.Read, 4096, false); }
                catch { data.Dispose(); throw; }
                lease.Check();
                return lease;
            } catch { lease.Dispose(); throw; }
        }
        public byte[] Capture(int minimum, int maximum)
        {
            if (stream == null) throw new ObjectDisposedException("PlatformInputLease");
            if (minimum < 0 || maximum < minimum || maximum > 65536)
                throw new InvalidDataException("Public capture bounds are invalid.");
            Check();
            long length = stream.Length;
            if (length < minimum || length > maximum) throw new InvalidDataException("Public input length exceeds the exact bound.");
            byte[] result = new byte[(int)length];
            stream.Position = 0;
            int position = 0;
            while (position < result.Length) {
                Check();
                int read = stream.Read(result, position, Math.Min(32768, result.Length-position));
                if (read == 0) throw new InvalidDataException("Public input truncated during capture.");
                position += read;
            }
            if (stream.ReadByte() != -1) throw new InvalidDataException("Public input grew during capture.");
            Check();
            return result;
        }
        public void Check()
        {
            if (stream == null) throw new ObjectDisposedException("PlatformInputLease");
            for (int i=0; i<handles.Count; i++) if (!Same(initial[i], Inspect(handles[i], directories[i])))
                throw new InvalidDataException("A held public input or ancestor changed metadata.");
            if (!Same(initial[initial.Count-1], Inspect(stream.SafeFileHandle, false)))
                throw new InvalidDataException("Held public input data object changed metadata.");
        }
        public void Dispose()
        {
            if (stream != null) { stream.Dispose(); stream = null; }
            foreach (SafeFileHandle file in handles) file.Dispose();
            handles.Clear(); initial.Clear(); directories.Clear();
        }
    }
}
