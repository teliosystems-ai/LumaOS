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
}
