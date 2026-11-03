// Held public VHDX data inspection only; never VM, custody or firmware authority.
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Luma.Windows
{
    public sealed class HyperVImageLease : IDisposable
    {
        public const long MaximumBytes = 16324231168L;
        private PlatformInputLease identity;
        private FileStream data;
        public string Sha256 { get; private set; }
        public long Bytes { get; private set; }

        public static HyperVImageLease Acquire(string path, string expectedSha256, long expectedBytes)
        {
            if (expectedSha256 == null || !Regex.IsMatch(expectedSha256, "\\A[a-f0-9]{64}\\z") ||
                expectedBytes < 1048576 || expectedBytes > MaximumBytes)
                throw new InvalidDataException("Explicit bounded VHDX length and independent SHA256 required.");
            HyperVImageLease lease = new HyperVImageLease();
            try {
                // This existing primitive holds every ancestor and the selected
                // single-link local disk file with no WRITE/DELETE sharing.
                lease.identity = PlatformInputLease.Acquire(path);
                lease.data = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    1048576, FileOptions.SequentialScan);
                lease.Bytes = expectedBytes;
                lease.Check();
                byte[] magic = new byte[8];
                if (lease.data.Read(magic, 0, magic.Length) != 8 ||
                    System.Text.Encoding.ASCII.GetString(magic) != "vhdxfile")
                    throw new InvalidDataException("Selected media is not actual VHDX data.");
                lease.data.Position = 0;
                byte[] buffer = new byte[1048576];
                long remaining = expectedBytes;
                Stopwatch elapsed = Stopwatch.StartNew();
                using (SHA256 hash = SHA256.Create()) {
                    while (remaining > 0) {
                        // Synchronous filesystem calls have no hard completion
                        // deadline. This bounds observed progress between calls.
                        if (elapsed.Elapsed > TimeSpan.FromMinutes(30))
                            throw new IOException("VHDX hashing observation deadline exceeded.");
                        lease.Check();
                        int count = lease.data.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                        if (count == 0) throw new EndOfStreamException("Held VHDX truncated.");
                        hash.TransformBlock(buffer, 0, count, null, 0);
                        remaining -= count;
                    }
                    if (lease.data.ReadByte() != -1) throw new InvalidDataException("Held VHDX grew.");
                    hash.TransformFinalBlock(new byte[0], 0, 0);
                    lease.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
                }
                lease.Check();
                if (!String.Equals(lease.Sha256, expectedSha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Independent held VHDX SHA256 differs.");
                return lease;
            } catch { lease.Dispose(); throw; }
        }

        public void Check()
        {
            if (identity == null || data == null) throw new ObjectDisposedException("HyperVImageLease");
            identity.Check();
            if (data.Length != Bytes) throw new InvalidDataException("Held VHDX exact length changed.");
        }

        public void Dispose()
        {
            if (data != null) { data.Dispose(); data = null; }
            if (identity != null) { identity.Dispose(); identity = null; }
        }
    }

    // A downloaded ISO or VHDX held with no WRITE/DELETE sharing while its
    // SHA256 is compared with a SHA256SUMS entry. Integrity only: a listed
    // digest from the same download location never authenticates origin.
    public sealed class HyperVMediaLease : IDisposable
    {
        public const long MinimumBytes = 1048576L;
        public const long MaximumBytes = 68719476736L;
        private PlatformInputLease identity;
        private FileStream data;
        public string Kind { get; private set; }
        public string Sha256 { get; private set; }
        public long Bytes { get; private set; }

        public static string KindOf(string path)
        {
            string extension = Path.GetExtension(path ?? "");
            if (String.Equals(extension, ".iso", StringComparison.Ordinal)) return "iso";
            if (String.Equals(extension, ".vhdx", StringComparison.Ordinal)) return "vhdx";
            throw new InvalidDataException("Downloaded Hyper-V media must be a lowercase .iso or .vhdx file.");
        }

        public static HyperVMediaLease Acquire(string path, string expectedSha256)
        {
            if (expectedSha256 == null || !Regex.IsMatch(expectedSha256, "\\A[a-f0-9]{64}\\z"))
                throw new InvalidDataException("A canonical listed media SHA256 is required.");
            HyperVMediaLease lease = new HyperVMediaLease();
            try {
                lease.Kind = KindOf(path);
                lease.identity = PlatformInputLease.Acquire(path);
                lease.data = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    1048576, FileOptions.SequentialScan);
                lease.Bytes = lease.data.Length;
                if (lease.Bytes < MinimumBytes || lease.Bytes > MaximumBytes)
                    throw new InvalidDataException("Downloaded media length is outside the closed 1MiB-64GiB bound.");
                lease.Check();
                RequireMagic(lease.data, lease.Kind);
                lease.Sha256 = lease.Digest(null);
                if (!String.Equals(lease.Sha256, expectedSha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Downloaded media SHA256 differs from its SHA256SUMS entry.");
                return lease;
            } catch { lease.Dispose(); throw; }
        }

        private static void RequireMagic(FileStream stream, string kind)
        {
            // ISO9660 primary descriptor identifier at sector 16 byte 1; VHDX
            // file type identifier at byte 0. Content checks, not boot checks.
            long offset = kind == "iso" ? 32769L : 0L;
            string expected = kind == "iso" ? "CD001" : "vhdxfile";
            byte[] magic = new byte[expected.Length];
            stream.Position = offset;
            int read = 0;
            while (read < magic.Length) {
                int count = stream.Read(magic, read, magic.Length - read);
                if (count == 0) break;
                read += count;
            }
            stream.Position = 0;
            if (read != magic.Length || System.Text.Encoding.ASCII.GetString(magic) != expected)
                throw new InvalidDataException("Downloaded media content does not match its " + kind + " extension.");
        }

        private string Digest(Stream copy)
        {
            data.Position = 0;
            byte[] buffer = new byte[1048576];
            long remaining = Bytes;
            Stopwatch elapsed = Stopwatch.StartNew();
            using (SHA256 hash = SHA256.Create()) {
                while (remaining > 0) {
                    // Bounds observed progress between synchronous calls only.
                    if (elapsed.Elapsed > TimeSpan.FromMinutes(120))
                        throw new IOException("Media hashing observation deadline exceeded.");
                    Check();
                    int count = data.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                    if (count == 0) throw new EndOfStreamException("Held media truncated.");
                    hash.TransformBlock(buffer, 0, count, null, 0);
                    if (copy != null) copy.Write(buffer, 0, count);
                    remaining -= count;
                }
                if (data.ReadByte() != -1) throw new InvalidDataException("Held media grew.");
                hash.TransformFinalBlock(new byte[0], 0, 0);
                Check();
                return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
            }
        }

        // Writes a new file only (never replaces), hashes the held source while
        // writing, flushes to disk, then re-reads the closed copy through a new
        // held lease. Returns the copy's verified SHA256.
        public string CopyTo(string destination)
        {
            Check();
            PlatformInputLease.ValidatePath(destination);
            if (!String.Equals(Path.GetExtension(destination), "." + Kind, StringComparison.Ordinal))
                throw new InvalidDataException("Media copy must keep its verified kind.");
            using (FileStream output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 1048576, FileOptions.None)) {
                string written = Digest(output);
                output.Flush(true);
                if (output.Length != Bytes || !String.Equals(written, Sha256, StringComparison.Ordinal))
                    throw new InvalidDataException("Held media changed while it was copied.");
            }
            using (HyperVMediaLease copy = Acquire(destination, Sha256)) {
                if (copy.Bytes != Bytes) throw new InvalidDataException("Media copy length differs.");
                return copy.Sha256;
            }
        }

        public void Check()
        {
            if (identity == null || data == null) throw new ObjectDisposedException("HyperVMediaLease");
            identity.Check();
            if (data.Length != Bytes) throw new InvalidDataException("Held media exact length changed.");
        }

        public void Dispose()
        {
            if (data != null) { data.Dispose(); data = null; }
            if (identity != null) { identity.Dispose(); identity = null; }
        }
    }
}
