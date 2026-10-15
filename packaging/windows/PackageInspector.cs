using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Luma.Windows
{
    public sealed class RequiredFile
    {
        public string Path;
        public long Bytes;
        public string Sha256;
        public bool Executable;
    }

    public sealed class PackageContent
    {
        public long ArchiveBytes;
        public long ContentBytes;
        public int MemberCount;
        public string ArchiveSha256;
        public string OsRelease;
        public string WslConfiguration;
        public string PlatformIdentity;
    }

    // No archive is extracted and no member name is passed to filesystem APIs.
    public sealed class PackageInspector
    {
        public const long MaximumArchiveBytes = 16L * 1024 * 1024 * 1024;
        public const int MaximumMembers = 200000;
        private readonly Stopwatch elapsed = Stopwatch.StartNew();
        private readonly SHA256 archiveHash = SHA256.Create();
        private readonly FileStream input;
        private readonly byte[] header = new byte[512];
        private readonly byte[] buffer = new byte[65536];
        private readonly Dictionary<string, bool> members = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> exactMembers = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, RequiredFile> required = new Dictionary<string, RequiredFile>(StringComparer.Ordinal);
        private readonly HashSet<string> observedRequired = new HashSet<string>(StringComparer.Ordinal);

        private PackageInspector(FileStream source, RequiredFile[] expected)
        {
            input = source;
            foreach (RequiredFile file in expected) required.Add(file.Path, file);
        }

        public static byte[] ReadManifest(string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (stream.Length == 0 || stream.Length > 65536) throw new InvalidDataException("Manifest size outside fixed bound.");
                byte[] bytes = new byte[(int)stream.Length];
                int offset = 0;
                while (offset < bytes.Length)
                {
                    int count = stream.Read(bytes, offset, bytes.Length - offset);
                    if (count == 0) throw new EndOfStreamException("Manifest changed or was truncated.");
                    offset += count;
                }
                if (stream.ReadByte() != -1) throw new InvalidDataException("Manifest changed during inspection.");
                return bytes;
            }
        }

        public static string Sha256(byte[] bytes)
        {
            using (SHA256 digest = SHA256.Create()) return Hex(digest.ComputeHash(bytes));
        }

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        public static string ValidatePath(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > 255 || path.StartsWith("/") || path.EndsWith("/"))
                throw new InvalidDataException("Archive path is empty, absolute, too long or noncanonical.");
            foreach (string part in path.Split('/'))
            {
                if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") ||
                    !Regex.IsMatch(part, @"\A[A-Za-z0-9_][A-Za-z0-9._+@=-]*\z") ||
                    Regex.IsMatch(part, @"\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\z)", RegexOptions.IgnoreCase))
                    throw new InvalidDataException("Archive path contains traversal, ambiguous or unsupported components.");
            }
            return path;
        }

        private void ReadExactly(byte[] bytes, int count)
        {
            int position = 0;
            while (position < count)
            {
                if (elapsed.Elapsed.TotalSeconds > 300) throw new InvalidDataException("Archive inspection exceeds fixed time bound.");
                int read = input.Read(bytes, position, count - position);
                if (read == 0) throw new EndOfStreamException("Truncated archive member or padding.");
                archiveHash.TransformBlock(bytes, position, read, bytes, position);
                position += read;
            }
        }

        private static bool Zero(byte[] bytes, int start, int count)
        {
            for (int index = start; index < start + count; index++) if (bytes[index] != 0) return false;
            return true;
        }

        private static string Field(byte[] bytes, int start, int count)
        {
            int length = 0;
            while (length < count && bytes[start + length] != 0)
            {
                if (bytes[start + length] < 32 || bytes[start + length] > 126)
                    throw new InvalidDataException("Archive header contains unsupported text encoding.");
                length++;
            }
            if (length < count && !Zero(bytes, start + length, count - length))
                throw new InvalidDataException("Archive header contains hidden field suffix bytes.");
            return Encoding.ASCII.GetString(bytes, start, length);
        }

        private static long Octal(byte[] bytes, int start, int count, bool emptyAllowed)
        {
            int end = start + count;
            int position = start;
            while (position < end && bytes[position] == 32) position++;
            long value = 0;
            bool found = false;
            while (position < end && bytes[position] >= 48 && bytes[position] <= 55)
            {
                value = checked(value * 8 + bytes[position] - 48);
                position++;
                found = true;
            }
            while (position < end && (bytes[position] == 0 || bytes[position] == 32)) position++;
            if (position != end || (!found && !emptyAllowed))
                throw new InvalidDataException("Archive numeric metadata is not bounded POSIX octal.");
            return value;
        }

        private static string Utf8(byte[] bytes)
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }

        private static void CheckPlatformElf(byte[] bytes)
        {
            if (bytes.Length < 64 || bytes[0] != 0x7f || bytes[1] != 69 || bytes[2] != 76 || bytes[3] != 70 ||
                bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 ||
                (bytes[16] != 2 && bytes[16] != 3) || bytes[17] != 0 || bytes[18] != 62 || bytes[19] != 0 ||
                bytes[20] != 1 || bytes[21] != 0 || bytes[22] != 0 || bytes[23] != 0 ||
                bytes[52] != 64 || bytes[53] != 0 || (bytes[56] == 0 && bytes[57] == 0))
                throw new InvalidDataException("Platform file is not an amd64 little-endian executable ELF header.");
        }

        private PackageContent Inspect(long expectedBytes, long expectedContentBytes, int expectedMembers, string expectedSha)
        {
            if (input.Length != expectedBytes || expectedBytes < 1536 || expectedBytes > MaximumArchiveBytes || expectedBytes % 512 != 0)
                throw new InvalidDataException("Archive byte size is inconsistent or outside fixed bounds.");
            PackageContent result = new PackageContent();
            bool ended = false;
            while (input.Position < input.Length)
            {
                ReadExactly(header, 512);
                if (Zero(header, 0, 512))
                {
                    ReadExactly(header, 512);
                    if (!Zero(header, 0, 512)) throw new InvalidDataException("Archive lacks two canonical zero end blocks.");
                    if (input.Length - input.Position > 10240) throw new InvalidDataException("Archive trailing padding exceeds fixed bound.");
                    while (input.Position < input.Length)
                    {
                        ReadExactly(header, 512);
                        if (!Zero(header, 0, 512)) throw new InvalidDataException("Trailing archive data or concatenated archive refused.");
                    }
                    ended = true;
                    break;
                }
                if (++result.MemberCount > MaximumMembers) throw new InvalidDataException("Archive member count exceeds fixed bound.");
                if (Field(header, 257, 6) != "ustar" || header[262] != 0 || header[263] != 48 || header[264] != 48)
                    throw new InvalidDataException("Only uncompressed POSIX USTAR rootfs is accepted; native raw/compressed images are not rootfs archives.");
                long checksum = 0;
                for (int index = 0; index < 512; index++) checksum += index >= 148 && index < 156 ? 32 : header[index];
                if (checksum != Octal(header, 148, 8, false)) throw new InvalidDataException("Archive header checksum mismatch.");
                byte kind = header[156];
                bool directory = kind == 53;
                if (kind != 0 && kind != 48 && !directory)
                    throw new InvalidDataException("Links, extension records, sparse members and special files are forbidden.");
                if (!Zero(header, 157, 100) || !Zero(header, 500, 12) ||
                    Octal(header, 329, 8, true) != 0 || Octal(header, 337, 8, true) != 0)
                    throw new InvalidDataException("Archive contains link/device/reserved metadata.");
                Field(header, 265, 32);
                Field(header, 297, 32);
                if (Octal(header, 108, 8, false) != 0 || Octal(header, 116, 8, false) != 0)
                    throw new InvalidDataException("Normalized rootfs members must be root owned.");
                Octal(header, 136, 12, false);
                long size = Octal(header, 124, 12, false);
                long mode = Octal(header, 100, 8, false);
                if (mode > 1023 || (mode & 3072) != 0 || (!directory && (mode & 512) != 0) ||
                    ((mode & 18) != 0 && !(directory && mode == 1023)))
                    throw new InvalidDataException("Archive contains privileged or unsafe writable permissions.");
                string name = Field(header, 0, 100);
                string prefix = Field(header, 345, 155);
                string path = (prefix.Length == 0 ? "" : prefix + "/") + name;
                if (directory && path.EndsWith("/")) path = path.Substring(0, path.Length - 1);
                ValidatePath(path);
                if (members.ContainsKey(path)) throw new InvalidDataException("Duplicate or case-aliased archive path.");
                members.Add(path, directory);
                exactMembers.Add(path);
                if (directory && size != 0) throw new InvalidDataException("Directory contains payload bytes.");
                if (size > MaximumArchiveBytes || input.Length - input.Position < size)
                    throw new InvalidDataException("Archive member size exceeds available bytes.");
                result.ContentBytes = checked(result.ContentBytes + size);
                if (result.ContentBytes > MaximumArchiveBytes) throw new InvalidDataException("Archive content sum exceeds fixed bound.");
                RequiredFile expectation;
                bool selected = required.TryGetValue(path, out expectation);
                if (selected && (directory || expectation.Bytes != size || expectation.Executable != ((mode & 73) != 0)))
                    throw new InvalidDataException("Required member type, byte size or executable status differs.");
                int captureBound = path == "usr/bin/luma-platform" ? 64 : 16384;
                if (selected && path == "usr/lib/luma/platform.json") captureBound = 4096;
                MemoryStream captured = selected ? new MemoryStream() : null;
                using (SHA256 memberHash = selected ? SHA256.Create() : null)
                {
                    long left = size;
                    while (left > 0)
                    {
                        int count = (int)Math.Min(left, buffer.Length);
                        ReadExactly(buffer, count);
                        if (selected)
                        {
                            memberHash.TransformBlock(buffer, 0, count, buffer, 0);
                            int take = (int)Math.Min(count, Math.Max(0, captureBound - captured.Length));
                            captured.Write(buffer, 0, take);
                        }
                        left -= count;
                    }
                    if (selected)
                    {
                        memberHash.TransformFinalBlock(new byte[0], 0, 0);
                        if (Hex(memberHash.Hash) != expectation.Sha256) throw new InvalidDataException("Required member SHA256 mismatch.");
                        observedRequired.Add(path);
                        byte[] bytes = captured.ToArray();
                        if (path == "usr/bin/luma-platform") CheckPlatformElf(bytes);
                        else if (path == "etc/os-release") result.OsRelease = Utf8(bytes);
                        else if (path == "etc/wsl.conf") result.WslConfiguration = Utf8(bytes);
                        else if (path == "usr/lib/luma/platform.json") result.PlatformIdentity = Utf8(bytes);
                    }
                }
                if (captured != null) captured.Dispose();
                int padding = (int)((512 - size % 512) % 512);
                ReadExactly(buffer, padding);
                if (!Zero(buffer, 0, padding)) throw new InvalidDataException("Archive member padding is nonzero.");
            }
            if (!ended || result.MemberCount != expectedMembers || result.ContentBytes != expectedContentBytes ||
                observedRequired.Count != required.Count) throw new InvalidDataException("Archive termination, counts, content size or required members differ.");
            foreach (string path in members.Keys)
            {
                if (elapsed.Elapsed.TotalSeconds > 300) throw new InvalidDataException("Archive inspection exceeds fixed time bound.");
                int slash = path.LastIndexOf('/');
                while (slash >= 0)
                {
                    string parent = path.Substring(0, slash);
                    bool isDirectory;
                    if (!members.TryGetValue(parent, out isDirectory) || !isDirectory)
                        throw new InvalidDataException("Archive parent is missing, case-aliased or not a directory.");
                    // Dictionary aliases are rejected, including differently cased parent spelling.
                    if (!exactMembers.Contains(parent)) throw new InvalidDataException("Archive parent spelling is not canonical.");
                    slash = parent.LastIndexOf('/');
                }
            }
            archiveHash.TransformFinalBlock(new byte[0], 0, 0);
            result.ArchiveSha256 = Hex(archiveHash.Hash);
            result.ArchiveBytes = input.Length;
            if (result.ArchiveSha256 != expectedSha) throw new InvalidDataException("Archive SHA256 differs from the exact manifest bytes.");
            return result;
        }

        public static PackageContent Validate(string path, long bytes, long contentBytes, int memberCount, string sha256, RequiredFile[] expected)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                PackageInspector inspector = new PackageInspector(stream, expected);
                try { return inspector.Inspect(bytes, contentBytes, memberCount, sha256); }
                finally { inspector.archiveHash.Dispose(); }
            }
        }
    }
}
