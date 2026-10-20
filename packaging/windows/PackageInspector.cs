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
        public readonly Dictionary<string, string> HostedConfiguration = new Dictionary<string, string>(StringComparer.Ordinal);
        internal string ValidatedBinding;
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
        private readonly Action continuous;

        private PackageInspector(FileStream source, RequiredFile[] expected, Action continuous)
        {
            input = source;
            this.continuous = continuous;
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
                if (continuous != null) continuous();
                if (elapsed.Elapsed.TotalSeconds > 300) throw new InvalidDataException("Archive inspection exceeds fixed time bound.");
                int read = input.Read(bytes, position, count - position);
                if (read == 0) throw new EndOfStreamException("Truncated archive member or padding.");
                archiveHash.TransformBlock(bytes, position, read, bytes, position);
                position += read;
                if (continuous != null) continuous();
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
                if(!directory && path.StartsWith("usr/libexec/luma-os/hosted-llama/",StringComparison.Ordinal) && !selected)
                    throw new InvalidDataException("Every private inference runtime member must be independently required by the authenticated release.");
                if (selected && (directory || expectation.Bytes != size || expectation.Executable != ((mode & 73) != 0)))
                    throw new InvalidDataException("Required member type, byte size or executable status differs.");
                bool platformElf = path == "usr/bin/luma-platform" || path == "usr/libexec/luma-os/luma-platform" || path == "usr/libexec/luma-os/luma-workspace-auth-helper" || path=="bin/bash";
                int captureBound = platformElf ? 64 : 16384;
                if (selected && (path == "etc/apparmor.d/luma-hosted-compute" || path == "etc/apparmor.d/luma-hosted-inference" || path=="etc/apparmor.d/luma-hosted-workspace-bootstrap")) captureBound = 1024 * 1024;
                if(selected && (path=="usr/share/luma-os/hosted-workspace.json" || path=="usr/share/luma-os/hosted-workspace-runtime.json")) captureBound=32768;
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
                        if (platformElf) CheckPlatformElf(bytes);
                        else if (path == "etc/os-release") result.OsRelease = Utf8(bytes);
                        else if (path == "etc/wsl.conf") result.WslConfiguration = Utf8(bytes);
                        else if (path == "usr/lib/luma/platform.json") result.PlatformIdentity = Utf8(bytes);
                        else if (path == "etc/passwd" || path == "etc/group" || path == "etc/shadow" || path == "etc/gshadow" ||
                            path == "etc/systemd/system/luma-hosted-confinement.service" ||
                            path == "etc/systemd/system/multi-user.target.wants/luma-hosted-confinement.service" ||
                            path == "etc/apparmor.d/luma-hosted-compute" || path == "etc/apparmor.d/luma-hosted-inference" ||
                            path == "etc/systemd/system/luma-hosted-inference-confinement.service" ||
                            path == "etc/systemd/system/multi-user.target.wants/luma-hosted-inference-confinement.service" ||
                            path == "usr/share/luma-os/hosted-inference.json" || path == "usr/share/luma-os/hosted-inference-runtime.json" || WorkspaceConfiguration(path))
                        {
                            int wantedMode = path == "etc/shadow" || path == "etc/gshadow" ? 384 : 420;
                            if (mode != wantedMode) throw new InvalidDataException("Hosted configuration permissions differ from the closed profile.");
                            if (size > captureBound) throw new InvalidDataException("Hosted configuration exceeds its capture bound.");
                            result.HostedConfiguration.Add(path, Utf8(bytes));
                        }
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
                if (continuous != null) continuous();
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
            result.ValidatedBinding = ContentBinding(result, new List<RequiredFile>(required.Values).ToArray());
            if (continuous != null) continuous();
            return result;
        }

        private static string ContentBinding(PackageContent content, RequiredFile[] files)
        {
            if (content == null || files == null || files.Length < 4 || files.Length > 128 ||
                (files.Length > 64 && !InferenceIdentity(content.PlatformIdentity) && !WorkspaceIdentity(content.PlatformIdentity))) throw new InvalidDataException("Actual bounded package inspection is required; only closed inference/workspace identities permit 65..128 required files.");
            foreach (RequiredFile file in files)
                if (file == null || String.IsNullOrEmpty(file.Path) || file.Bytes < 0 ||
                    file.Sha256 == null || !Regex.IsMatch(file.Sha256, "\\A[a-f0-9]{64}\\z", RegexOptions.CultureInvariant))
                    throw new InvalidDataException("Package inspection binding has an invalid required-file record.");
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                writer.Write("luma-inspected-package-binding-v1");
                writer.Write(content.ArchiveSha256 ?? ""); writer.Write(content.ArchiveBytes);
                writer.Write(content.ContentBytes); writer.Write(content.MemberCount);
                writer.Write(content.PlatformIdentity ?? ""); writer.Write(content.OsRelease ?? ""); writer.Write(content.WslConfiguration ?? "");
                List<string> names = new List<string>(content.HostedConfiguration.Keys); names.Sort(StringComparer.Ordinal);
                foreach (string name in names) { writer.Write(name); writer.Write(content.HostedConfiguration[name]); }
                List<RequiredFile> sorted = new List<RequiredFile>(files); sorted.Sort((a, b) => String.CompareOrdinal(a.Path, b.Path));
                foreach (RequiredFile file in sorted)
                {
                    writer.Write(file.Path); writer.Write(file.Bytes); writer.Write(file.Sha256); writer.Write(file.Executable);
                }
                writer.Flush(); return Sha256(stream.ToArray());
            }
        }

        // This validates an already inspected compute composition. It supplies
        // neither release-signature authority nor a live runtime/TPM permit.
        public static void ValidateHostedProfile(PackageContent content, RequiredFile[] files)
        {
            if (content == null || String.IsNullOrEmpty(content.ValidatedBinding) ||
                content.ValidatedBinding != ContentBinding(content, files))
                throw new InvalidDataException("Hosted validation requires the unchanged actual archive inspection.");
            const string identity = "\\A\\{\"architecture\":\"amd64\",\"profile\":\"W\",\"release_id\":\"luma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}\",\"runtime_profile\":\"luma-windows-hosted-(?:compute|inference)-v1\",\"schema_version\":2\\}\\n\\z";
            if (!Regex.IsMatch(content.PlatformIdentity, identity, RegexOptions.CultureInvariant) && !WorkspaceIdentity(content.PlatformIdentity))
                throw new InvalidDataException("Hosted identity must be the exact schema-2 compute package identity.");
            const string wsl = "[boot]\nsystemd=true\n[automount]\nenabled=false\n[interop]\nenabled=false\nappendWindowsPath=false\n[user]\ndefault=nobody\n";
            if (content.WslConfiguration != wsl) throw new InvalidDataException("Hosted WSL configuration differs.");
            Dictionary<string, string> os = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string line in content.OsRelease.Split('\n'))
            {
                if (!line.StartsWith("ID=", StringComparison.Ordinal) && !line.StartsWith("VERSION_ID=", StringComparison.Ordinal)) continue;
                Match match = Regex.Match(line, "\\A(ID|VERSION_ID)=(?:\"([A-Za-z0-9.]+)\"|([A-Za-z0-9.]+))\\z", RegexOptions.CultureInvariant);
                if (!match.Success || os.ContainsKey(match.Groups[1].Value)) throw new InvalidDataException("Hosted Ubuntu identity is ambiguous.");
                os.Add(match.Groups[1].Value, match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value);
            }
            if (os.Count != 2 || os["ID"] != "ubuntu" || os["VERSION_ID"] != "24.04") throw new InvalidDataException("Hosted runtime requires actual Ubuntu 24.04 identity.");
            const string unit = "[Unit]\nDescription=Luma hosted inert compute confinement\nDefaultDependencies=no\nAfter=systemd-remount-fs.service\nBefore=multi-user.target\nConditionSecurity=apparmor\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/apparmor_parser --add --skip-cache /etc/apparmor.d/luma-hosted-compute\nRemainAfterExit=yes\nTimeoutStartSec=15\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_MAC_ADMIN\nAmbientCapabilities=\nProtectHome=yes\nPrivateTmp=yes\nProtectSystem=strict\nRestrictAddressFamilies=AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n";
            Dictionary<string, string> configuration = new Dictionary<string, string>(StringComparer.Ordinal) {
                {"etc/passwd", "root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n"},
                {"etc/group", "root:x:0:\nnogroup:x:65534:\n"},
                {"etc/shadow", "root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n"},
                {"etc/gshadow", "root:!::\nnogroup:!::\n"},
                {"etc/systemd/system/luma-hosted-confinement.service", unit},
                {"etc/systemd/system/multi-user.target.wants/luma-hosted-confinement.service", unit}
            };
            Dictionary<string, RequiredFile> selected = new Dictionary<string, RequiredFile>(StringComparer.Ordinal);
            foreach (RequiredFile file in files) selected.Add(file.Path, file);
            foreach (KeyValuePair<string, string> pair in configuration)
            {
                string actual; RequiredFile file;
                if (!content.HostedConfiguration.TryGetValue(pair.Key, out actual) || actual != pair.Value ||
                    !selected.TryGetValue(pair.Key, out file) || file.Executable)
                    throw new InvalidDataException("Hosted fixed account or service configuration differs.");
            }
            foreach (string path in new string[] {"usr/bin/luma-platform", "usr/libexec/luma-os/luma-platform", "usr/bin/systemd-run", "usr/bin/systemctl", "usr/sbin/apparmor_parser"})
            {
                RequiredFile file;
                if (!selected.TryGetValue(path, out file) || !file.Executable || file.Bytes < 64 || file.Bytes > 64 * 1024 * 1024)
                    throw new InvalidDataException("Hosted fixed executable is missing or exceeds bounds.");
            }
            if (selected["usr/bin/luma-platform"].Sha256 != selected["usr/libexec/luma-os/luma-platform"].Sha256 ||
                selected["usr/bin/luma-platform"].Bytes != selected["usr/libexec/luma-os/luma-platform"].Bytes)
                throw new InvalidDataException("Hosted platform executable aliases differ.");
            const string policyPath = "etc/apparmor.d/luma-hosted-compute";
            string policy; RequiredFile policyFile;
            if (!selected.TryGetValue(policyPath, out policyFile) || policyFile.Executable || policyFile.Bytes < 1 || policyFile.Bytes > 1024 * 1024 ||
                !content.HostedConfiguration.TryGetValue(policyPath, out policy) ||
                Regex.IsMatch(policy, "(?m)^[ \\t]*(?:#[ \\t]*)?include(?:[ \\t]|$)", RegexOptions.CultureInvariant) ||
                !policy.Contains("profile luma-hosted-compute ") || !policy.Contains("deny network,"))
                throw new InvalidDataException("Hosted policy is missing, unresolved or outside the closed compute profile.");
            if(InferenceIdentity(content.PlatformIdentity) || WorkspaceIdentity(content.PlatformIdentity) && (content.HostedConfiguration.ContainsKey("usr/share/luma-os/hosted-inference.json") || content.HostedConfiguration.ContainsKey("usr/share/luma-os/hosted-inference-runtime.json"))) {
                const string prefix="etc/systemd/system/",leaf="luma-hosted-inference-confinement.service";
                string inferenceUnit=unit.Replace("hosted inert compute","hosted compact inference").Replace("luma-hosted-compute","luma-hosted-inference");
                foreach(string name in new string[]{prefix+leaf,prefix+"multi-user.target.wants/"+leaf}) {
                    string actual;RequiredFile expected;
                    if(!content.HostedConfiguration.TryGetValue(name,out actual) || actual!=inferenceUnit || !selected.TryGetValue(name,out expected) || expected.Executable)
                        throw new InvalidDataException("Inference confinement loader is missing or differs from the closed independent unit.");
                }
                const string inferencePolicy="etc/apparmor.d/luma-hosted-inference";
                if(!selected.TryGetValue(inferencePolicy,out policyFile) || policyFile.Executable || policyFile.Bytes<1 || policyFile.Bytes>1024*1024 ||
                    !content.HostedConfiguration.TryGetValue(inferencePolicy,out policy) || Regex.IsMatch(policy,"(?m)^[ \\t]*(?:#[ \\t]*)?include(?:[ \\t]|$)",RegexOptions.CultureInvariant) ||
                    !policy.Contains("profile luma-hosted-inference ") || !policy.Contains("deny network,")) throw new InvalidDataException("Inference policy is absent, unresolved or substituted.");
                string description,manifest;
                if(!content.HostedConfiguration.TryGetValue("usr/share/luma-os/hosted-inference.json",out description) ||
                    !content.HostedConfiguration.TryGetValue("usr/share/luma-os/hosted-inference-runtime.json",out manifest)) throw new InvalidDataException("Inference descriptors are absent from actual inspection.");
                ValidateInferenceDescriptors(description,manifest,files);
            }
            if(WorkspaceIdentity(content.PlatformIdentity)) {
                string description,manifest;
                if(!content.HostedConfiguration.TryGetValue("usr/share/luma-os/hosted-workspace.json",out description) || !content.HostedConfiguration.TryGetValue("usr/share/luma-os/hosted-workspace-runtime.json",out manifest))
                    throw new InvalidDataException("Workspace descriptors are absent from actual archive inspection.");
                ValidateWorkspaceDescriptors(description,manifest,files);
                foreach(KeyValuePair<string,string> pair in WorkspaceTemplates()) {
                    string actual;if(!content.HostedConfiguration.TryGetValue(pair.Key,out actual) || actual!=pair.Value) throw new InvalidDataException("Workspace exact PAM/NSS/baseline data differs from actual archive bytes.");
                }
                string workspaceUnit=unit.Replace("hosted inert compute","hosted first-account workspace").Replace("luma-hosted-compute","luma-hosted-workspace-bootstrap");
                foreach(string path in new string[]{"etc/systemd/system/luma-hosted-workspace-confinement.service","etc/systemd/system/multi-user.target.wants/luma-hosted-workspace-confinement.service"}) {
                    string actual;RequiredFile expected;if(!content.HostedConfiguration.TryGetValue(path,out actual) || actual!=workspaceUnit || !selected.TryGetValue(path,out expected) || expected.Executable)
                        throw new InvalidDataException("Workspace independent confinement deployment differs.");
                }
                const string workspacePolicy="etc/apparmor.d/luma-hosted-workspace-bootstrap";
                if(!selected.TryGetValue(workspacePolicy,out policyFile)||policyFile.Executable||policyFile.Bytes<1||policyFile.Bytes>1024*1024||!content.HostedConfiguration.TryGetValue(workspacePolicy,out policy)||
                    Regex.IsMatch(policy,"(?m)^[ \\t]*(?:#[ \\t]*)?include(?:[ \\t]|$)",RegexOptions.CultureInvariant)||!policy.Contains("profile luma-hosted-workspace-bootstrap ")||!policy.Contains("deny network,")||!policy.Contains("capability chown,"))
                    throw new InvalidDataException("Workspace confinement is absent, unresolved, or substituted.");
            }
        }

        private static bool InferenceIdentity(string identity)
        {return identity!=null && Regex.IsMatch(identity,"\\A\\{\"architecture\":\"amd64\",\"profile\":\"W\",\"release_id\":\"luma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}\",\"runtime_profile\":\"luma-windows-hosted-inference-v1\",\"schema_version\":2\\}\\n\\z",RegexOptions.CultureInvariant);}

        private static bool WorkspaceIdentity(string identity)
        {return identity!=null && Regex.IsMatch(identity,"\\A\\{\"architecture\":\"amd64\",\"profile\":\"W\",\"release_id\":\"luma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}\",\"runtime_profile\":\"luma-windows-hosted-workspace-v1\",\"schema_version\":3\\}\\n\\z",RegexOptions.CultureInvariant);}

        private static bool WorkspaceConfiguration(string path)
        {return path=="usr/share/luma-os/hosted-workspace.json"||path=="usr/share/luma-os/hosted-workspace-runtime.json"||path=="etc/pam.d/luma-admin"||path=="etc/nsswitch.conf"||
            path=="etc/apparmor.d/luma-hosted-workspace-bootstrap"||path=="etc/systemd/system/luma-hosted-workspace-confinement.service"||path=="etc/systemd/system/multi-user.target.wants/luma-hosted-workspace-confinement.service"||WorkspaceTemplates().ContainsKey(path);}

        private static Dictionary<string,string> WorkspaceTemplates()
        {
            const string prefix="usr/share/luma-os/hosted-workspace/accounts/";
            return new Dictionary<string,string>(StringComparer.Ordinal) {
                {prefix+"passwd","root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n"},
                {prefix+"group","root:x:0:\nnogroup:x:65534:\n"},{prefix+"shadow","root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n"},{prefix+"gshadow","root:!::\nnogroup:!::\n"},
                {"etc/nsswitch.conf","passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\n"},
                {"etc/pam.d/luma-admin","# Local Linux password/account verification, not a product Admin role.\nauth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so nodelay\naccount required /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n"}
            };
        }

        public static byte[] WorkspaceProfile(string runtime)
        {
            if(runtime==null||!Regex.IsMatch(runtime,"\\A[a-f0-9]{64}\\z",RegexOptions.CultureInvariant)||runtime==new string('0',64)) throw new InvalidDataException("Workspace runtime digest differs.");
            Dictionary<string,string> data=WorkspaceTemplates();const string prefix="usr/share/luma-os/hosted-workspace/accounts/";
            Func<string,string> hash=delegate(string name){return "\""+Sha256(Encoding.ASCII.GetBytes(data[name]))+"\"";};
            return Encoding.ASCII.GetBytes("{\"account_baselines\":{\"group\":"+hash(prefix+"group")+",\"gshadow\":"+hash(prefix+"gshadow")+",\"passwd\":"+hash(prefix+"passwd")+",\"shadow\":"+hash(prefix+"shadow")+
                "},\"account_generation\":1,\"account_gid\":1000,\"account_uid\":1000,\"bootstrap_cpu_seconds\":25,\"bootstrap_purpose_seconds\":30,\"cpu_period_usec\":100000,\"cpu_quota_usec\":100000,"+
                "\"default_uid\":65534,\"drain_seconds\":5,\"memory_max_bytes\":268435456,\"memory_swap_max_bytes\":0,\"nss_sha256\":"+hash("etc/nsswitch.conf")+",\"pam_sha256\":"+hash("etc/pam.d/luma-admin")+
                ",\"password_max_age_days\":90,\"profile\":\"luma-windows-hosted-workspace-v1\",\"runtime\":\"luma-windows-manual-workspace-v1\",\"runtime_manifest_sha256\":\""+runtime+"\",\"schema_version\":3,\"tasks_max\":8,\"wsl_flags\":0}\n");
        }

        public static void ValidateWorkspaceDescriptors(string description,string manifest,RequiredFile[] files)
        {
            if(description==null||manifest==null||description.Length>32768||manifest.Length>32768||files==null||files.Length<4||files.Length>128) throw new InvalidDataException("Workspace descriptor bounds differ.");
            const string profile="luma-windows-hosted-workspace-v1";
            Dictionary<string,RequiredFile> selected=new Dictionary<string,RequiredFile>(StringComparer.Ordinal);
            foreach(RequiredFile file in files){if(file==null||file.Path==null||selected.ContainsKey(file.Path))throw new InvalidDataException("Workspace publisher-required members are absent/duplicated.");selected.Add(file.Path,file);}
            string runtimeSha=Sha256(Encoding.ASCII.GetBytes(manifest));
            if(description!=Encoding.ASCII.GetString(WorkspaceProfile(runtimeSha))) throw new InvalidDataException("Workspace profile differs from the exact reviewed schema3 account/resource policy.");
            string record="\\{\"bytes\":([1-9][0-9]{0,8}),\"executable\":(true|false),\"path\":\"([A-Za-z0-9._/+-]{1,240})\",\"sha256\":\"([a-f0-9]{64})\"\\}";
            Match outer=Regex.Match(manifest,"\\A\\{\"files\":\\[("+record+"(?:,"+record+"){4,63})\\],\"profile\":\""+profile+"\",\"schema_version\":1\\}\\n\\z",RegexOptions.CultureInvariant);
            if(!outer.Success) throw new InvalidDataException("Workspace runtime manifest is not closed bounded canonical JSON.");
            string previous=null;HashSet<string> runtime=new HashSet<string>(StringComparer.Ordinal);
            foreach(Match member in Regex.Matches(outer.Groups[1].Value,record,RegexOptions.CultureInvariant)) {
                string path=ValidatePath(member.Groups[3].Value);long size=Int64.Parse(member.Groups[1].Value,System.Globalization.CultureInfo.InvariantCulture);bool executable=member.Groups[2].Value=="true";
                bool program=path=="usr/libexec/luma-os/luma-platform"||path=="usr/libexec/luma-os/luma-workspace-auth-helper"||path=="bin/bash";
                if(!program&&path!="usr/lib/x86_64-linux-gnu/security/pam_unix.so"&&!Regex.IsMatch(path,"\\A(?:usr/)?lib(?:64|/x86_64-linux-gnu)/[A-Za-z0-9._+-]*\\.so[A-Za-z0-9._+-]*\\z",RegexOptions.CultureInvariant)) throw new InvalidDataException("Workspace runtime escapes its closed fixed ELF/module namespace.");
                RequiredFile file;if(size<64||size>64*1024*1024||previous!=null&&String.CompareOrdinal(previous,path)>=0||!selected.TryGetValue(path,out file)||file.Bytes!=size||file.Executable!=executable||file.Sha256!=member.Groups[4].Value||program&&!executable)
                    throw new InvalidDataException("Workspace runtime member differs from exact publisher-required size/hash/mode/order.");
                runtime.Add(path);previous=path;
            }
            foreach(string path in new string[]{"usr/libexec/luma-os/luma-platform","usr/libexec/luma-os/luma-workspace-auth-helper","bin/bash","usr/lib/x86_64-linux-gnu/security/pam_unix.so"}) if(!runtime.Contains(path)) throw new InvalidDataException("Workspace omits its real worker/helper/PAM/login-shell closure.");
            foreach(KeyValuePair<string,string> pair in WorkspaceTemplates()) {byte[] bytes=Encoding.ASCII.GetBytes(pair.Value);RequireInferenceData(selected,pair.Key,bytes.Length,Sha256(bytes));}
            RequireInferenceData(selected,"usr/share/luma-os/hosted-workspace-runtime.json",Encoding.ASCII.GetByteCount(manifest),runtimeSha);
            RequireInferenceData(selected,"usr/share/luma-os/hosted-workspace.json",Encoding.ASCII.GetByteCount(description),Sha256(Encoding.ASCII.GetBytes(description)));
        }

        // Pure descriptor validation only. Callers still need actual archive
        // inspection, release authentication and live host admission separately.
        public static void ValidateInferenceDescriptors(string description,string manifest,RequiredFile[] files)
        {
            if(description==null || manifest==null || description.Length>8192 || manifest.Length>16384 || files==null || files.Length<4 || files.Length>128) throw new InvalidDataException("Inference descriptors exceed the closed bounds.");
            const string profile="luma-windows-hosted-inference-v1",model="usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf",modelSha="7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5";
            Dictionary<string,RequiredFile> selected=new Dictionary<string,RequiredFile>(StringComparer.Ordinal);
            foreach(RequiredFile file in files) {
                if(file==null || file.Path==null || selected.ContainsKey(file.Path)) throw new InvalidDataException("Inference required-file records are missing or duplicated.");selected.Add(file.Path,file);
            }
            string manifestSha=Sha256(new UTF8Encoding(false,true).GetBytes(manifest));
            string expected="{\"context_tokens\":2048,\"cpu_period_usec\":100000,\"cpu_quota_usec\":200000,\"environment\":\"lab\",\"maximum_output_tokens\":512,\"memory_max_bytes\":4831838208,\"memory_swap_max_bytes\":0,\"model_bytes\":2497280256,\"model_path\":\""+model+"\",\"model_sha256\":\""+modelSha+"\",\"profile\":\""+profile+"\",\"runtime\":\"llama.cpp-b11100-cpu-amd64-completion\",\"runtime_cpu_seconds\":300,\"runtime_manifest_sha256\":\""+manifestSha+"\",\"schema_version\":1,\"tasks_max\":16,\"threads\":2}\n";
            if(description!=expected) throw new InvalidDataException("Inference profile is not the exact canonical approved CPU-only model/resource descriptor.");
            string record="\\{\"bytes\":([1-9][0-9]{0,8}),\"executable\":(true|false),\"path\":\"([A-Za-z0-9._/+@=-]{1,255})\",\"sha256\":\"([a-f0-9]{64})\"\\}";
            Match outer=Regex.Match(manifest,"\\A\\{\"files\":\\[("+record+"(?:,"+record+"){0,63})\\],\"profile\":\""+profile+"\",\"schema_version\":1\\}\\n\\z",RegexOptions.CultureInvariant);
            if(!outer.Success) throw new InvalidDataException("Inference runtime manifest is not closed, bounded canonical JSON.");
            MatchCollection records=Regex.Matches(outer.Groups[1].Value,record,RegexOptions.CultureInvariant);HashSet<string> runtime=new HashSet<string>(StringComparer.Ordinal);string previous=null;
            foreach(Match item in records) {
                string path=ValidatePath(item.Groups[3].Value);long size=Int64.Parse(item.Groups[1].Value,System.Globalization.CultureInfo.InvariantCulture);bool executable=item.Groups[2].Value=="true";
                RequiredFile file;if(size<64 || size>64*1024*1024 || previous!=null && String.CompareOrdinal(previous,path)>=0 || !selected.TryGetValue(path,out file) || file.Bytes!=size || file.Executable!=executable || file.Sha256!=item.Groups[4].Value)
                    throw new InvalidDataException("Inference runtime member is unsorted, duplicated, unbounded or not exactly publisher-required.");
                if(path!="usr/libexec/luma-os/luma-platform" && !path.StartsWith("usr/libexec/luma-os/hosted-llama/",StringComparison.Ordinal) &&
                    !Regex.IsMatch(path,"\\A(?:usr/)?lib(?:64|/x86_64-linux-gnu)?/[A-Za-z0-9._+@=-]+\\z",RegexOptions.CultureInvariant)) throw new InvalidDataException("Inference runtime member escapes the fixed private/system ELF namespace.");
                runtime.Add(path);previous=path;
            }
            HashSet<string> privateNames=new HashSet<string>(StringComparer.Ordinal) {"llama-completion","libllama-completion-impl.so","libggml-cpu-x64.so"};
            foreach(string stem in new string[]{"libllama","libllama-common","libmtmd","libggml","libggml-base"}) {
                string version=stem=="libggml" || stem=="libggml-base"?"0.24.0":"0.4.1";privateNames.Add(stem+".so");privateNames.Add(stem+".so.0");privateNames.Add(stem+".so."+version);
            }
            const string privatePrefix="usr/libexec/luma-os/hosted-llama/";
            foreach(string name in privateNames) if(!runtime.Contains(privatePrefix+name)) throw new InvalidDataException("Inference runtime omits the fixed noninteractive completion program or a CPU-only dependency alias.");
            foreach(string name in runtime) if(name.StartsWith(privatePrefix,StringComparison.Ordinal) && !privateNames.Contains(name.Substring(privatePrefix.Length))) throw new InvalidDataException("Inference runtime contains an unapproved RPC, GPU, server program or private dependency.");
            foreach(string name in selected.Keys) if(name.StartsWith(privatePrefix,StringComparison.Ordinal) && !runtime.Contains(name)) throw new InvalidDataException("The selected package contains a private executable or plugin outside its exact inference runtime manifest.");
            if(!runtime.Contains("usr/libexec/luma-os/luma-platform")) throw new InvalidDataException("Inference runtime omits its exact native worker.");
            RequireInferenceData(selected,model,2497280256L,modelSha);
            RequireInferenceData(selected,"usr/share/luma-os/hosted-inference-runtime.json",new UTF8Encoding(false,true).GetByteCount(manifest),manifestSha);
            RequireInferenceData(selected,"usr/share/luma-os/hosted-inference.json",new UTF8Encoding(false,true).GetByteCount(description),Sha256(new UTF8Encoding(false,true).GetBytes(description)));
        }
        private static void RequireInferenceData(Dictionary<string,RequiredFile> selected,string path,long size,string sha)
        {RequiredFile file;if(!selected.TryGetValue(path,out file) || file.Bytes!=size || file.Executable || file.Sha256!=sha) throw new InvalidDataException("Inference model/descriptor differs from exact publisher-required non-executable data.");}

        public static PackageContent Validate(string path, long bytes, long contentBytes, int memberCount, string sha256, RequiredFile[] expected)
        {
            return ValidateCore(path, bytes, contentBytes, memberCount, sha256, expected, null);
        }

        public static PackageContent Validate(string path, long bytes, long contentBytes, int memberCount, string sha256, RequiredFile[] expected, Action continuous)
        {
            if (continuous == null) throw new ArgumentNullException("continuous");
            continuous();
            return ValidateCore(path, bytes, contentBytes, memberCount, sha256, expected, continuous);
        }

        private static PackageContent ValidateCore(string path, long bytes, long contentBytes, int memberCount, string sha256, RequiredFile[] expected, Action continuous)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                PackageInspector inspector = new PackageInspector(stream, expected, continuous);
                try { return inspector.Inspect(bytes, contentBytes, memberCount, sha256); }
                finally { inspector.archiveHash.Dispose(); }
            }
        }
    }
}
