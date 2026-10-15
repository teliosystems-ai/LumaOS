using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows
{
    public sealed class PackageDirectoryLease : IDisposable
    {
        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        public string DirectoryPath { get; private set; }
        private bool scratch;
        private bool disposed;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Disposition { public byte Delete; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool GetVolumeInformation(string root, StringBuilder name, uint nameSize,
            out uint serial, out uint maximumComponent, out uint flags, StringBuilder filesystem, uint filesystemSize);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind,
            ref Disposition disposition, uint length);

        private static SafeFileHandle OpenDirectory(string path, bool deletion)
        {
                // FILE_LIST_DIRECTORY is intentional: metadata-only opens do not
                // participate in Windows read/write/delete sharing arbitration.
                SafeFileHandle handle = CreateFile(path, 0x00020081U | (deletion ? 0x00010000U : 0),
                    3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "Cannot pin directory."); }
                try
                {
                    FileInformation information;
                    if (!GetFileInformationByHandle(handle, out information)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if ((information.Attributes & 0x10) == 0 || (information.Attributes & 0x400) != 0)
                        throw new InvalidDataException("Pinned path is not a real non-reparse directory.");
                    return handle;
                }
                catch { handle.Dispose(); throw; }
        }

        public static PackageDirectoryLease Acquire(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
                path.IndexOf('/') >= 0 || path.IndexOf(':', 2) >= 0)
                throw new InvalidDataException("Directory lease requires an absolute local Windows path.");
            string full=Path.GetFullPath(path), root=Path.GetPathRoot(full);
            if (!String.Equals(full.TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Directory lease path must be canonical without traversal.");
            PackageDirectoryLease lease=new PackageDirectoryLease();
            try
            {
                string current=root;
                lease.handles.Add(OpenDirectory(current,false));
                foreach (string component in full.Substring(root.Length).Split(new char[]{'\\'},StringSplitOptions.RemoveEmptyEntries))
                {
                    current=Path.Combine(current,component);
                    lease.handles.Add(OpenDirectory(current,false));
                }
                lease.DirectoryPath=full;
                return lease;
            }
            catch { lease.Dispose(); throw; }
        }

        private static void VerifyScratch(SafeFileHandle handle)
        {
            IntPtr owner,group,dacl,sacl,native;
            uint result=GetSecurityInfo(handle,1,5,out owner,out group,out dacl,out sacl,out native);
            if(result != 0) throw new Win32Exception((int)result,"Cannot read pinned file-object security.");
            byte[] bytes;
            try
            {
                uint needed=GetSecurityDescriptorLength(native);
                if (needed == 0 || needed > 65536) throw new InvalidDataException("Invalid scratch security descriptor bound.");
                bytes=new byte[needed];
                Marshal.Copy(native,bytes,0,bytes.Length);
            }
            finally { LocalFree(native); }
            RawSecurityDescriptor descriptor=new RawSecurityDescriptor(bytes,0);
            SecurityIdentifier self=WindowsIdentity.GetCurrent().User;
            SecurityIdentifier system=new SecurityIdentifier("S-1-5-18");
            if (!self.Equals(descriptor.Owner) ||
                (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                descriptor.DiscretionaryAcl == null || descriptor.DiscretionaryAcl.Count != 2)
                throw new InvalidDataException("Scratch owner or protected DACL differs from the atomic private creation policy (owner-match="+
                    self.Equals(descriptor.Owner)+", controls="+descriptor.ControlFlags+", ace-count="+
                    (descriptor.DiscretionaryAcl == null ? -1 : descriptor.DiscretionaryAcl.Count)+").");
            bool foundSelf=false,foundSystem=false;
            foreach (GenericAce raw in descriptor.DiscretionaryAcl)
            {
                CommonAce ace=raw as CommonAce;
                if (ace == null || ace.AceQualifier != AceQualifier.AccessAllowed ||
                    ace.AceFlags != (AceFlags.ContainerInherit | AceFlags.ObjectInherit) ||
                    ace.AccessMask != (int)FileSystemRights.FullControl || ace.IsCallback)
                    throw new InvalidDataException("Scratch DACL contains unsupported permissions.");
                if (ace.SecurityIdentifier.Equals(self) && !foundSelf) foundSelf=true;
                else if (ace.SecurityIdentifier.Equals(system) && !foundSystem) foundSystem=true;
                else throw new InvalidDataException("Scratch DACL contains an unexpected principal.");
            }
            if (!foundSelf || !foundSystem) throw new InvalidDataException("Scratch DACL is incomplete.");
        }

        public PackageDirectoryLease CreateScratch()
        {
            if (disposed || scratch) throw new InvalidOperationException("Scratch requires a live pinned parent chain.");
            uint serial,maximumComponent,flags;
            if (!GetVolumeInformation(Path.GetPathRoot(DirectoryPath),null,0,out serial,out maximumComponent,out flags,null,0))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot establish scratch volume ACL support.");
            if ((flags & 8) == 0) throw new InvalidDataException("Signature scratch volume does not support persistent ACLs.");
            DirectorySecurity security=new DirectorySecurity();
            security.SetAccessRuleProtection(true,false);
            SecurityIdentifier self=WindowsIdentity.GetCurrent().User;
            security.SetOwner(self);
            foreach (SecurityIdentifier sid in new SecurityIdentifier[]{self,new SecurityIdentifier("S-1-5-18")})
                security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            byte[] descriptor=security.GetSecurityDescriptorBinaryForm();
            IntPtr memory=Marshal.AllocHGlobal(descriptor.Length);
            string path=Path.Combine(DirectoryPath,"luma-signature-check-"+Guid.NewGuid().ToString("N"));
            try
            {
                Marshal.Copy(descriptor,0,memory,descriptor.Length);
                SecurityAttributes attributes=new SecurityAttributes();
                attributes.Length=Marshal.SizeOf(typeof(SecurityAttributes)); attributes.Descriptor=memory;
                if (!CreateDirectory(path,ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Atomic private scratch creation refused.");
            }
            finally { Marshal.FreeHGlobal(memory); }
            // A failed post-create verification deliberately does not delete an unverified pathname.
            PackageDirectoryLease lease=new PackageDirectoryLease();
            try
            {
                SafeFileHandle handle=OpenDirectory(path,true);
                lease.handles.Add(handle);
                VerifyScratch(handle);
                lease.DirectoryPath=path; lease.scratch=true;
                return lease;
            }
            catch { lease.Dispose(); throw; }
        }

        public void VerifyPrivateScratch()
        {
            if (disposed || !scratch) throw new InvalidOperationException("No live scratch lease.");
            VerifyScratch(handles[0]);
        }

        public void RemoveScratch()
        {
            if (disposed || !scratch) throw new InvalidOperationException("No live scratch lease.");
            VerifyScratch(handles[0]);
            foreach (string name in new string[]{"anchor.der","signature.bin","input.bin","empty.cnf"})
                File.Delete(Path.Combine(DirectoryPath,name));
            Disposition disposition=new Disposition(); disposition.Delete=1;
            if (!SetFileInformationByHandle(handles[0],4,ref disposition,1))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Pinned scratch cleanup refused; unknown content is retained.");
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed=true;
            for(int index=handles.Count-1;index>=0;index--) handles[index].Dispose();
        }
    }

    // Cryptographic observation only. This does not provision a trust anchor,
    // authenticate verifier dependencies, or establish protected current UTC.
    public static class PackageSignature
    {
        public static byte[] DecodeHex(string value, int count)
        {
            if (value == null || value.Length != count * 2 ||
                !System.Text.RegularExpressions.Regex.IsMatch(value, @"\A[0-9a-f]+\z"))
                throw new InvalidDataException("Noncanonical signature/key hex.");
            byte[] bytes = new byte[count];
            for (int index = 0; index < count; index++)
                bytes[index] = Convert.ToByte(value.Substring(index * 2, 2), 16);
            return bytes;
        }

        public static byte[] SigningInput(byte[] manifest, string environment)
        {
            if (manifest == null || manifest.Length == 0 || manifest.Length > 65536 ||
                (environment != "lab" && environment != "production"))
                throw new InvalidDataException("Invalid bounded signature input.");
            byte[] prefix = Encoding.ASCII.GetBytes("luma-wsl-package-v1\n" + environment + "\namd64\nW\n");
            byte[] result = new byte[prefix.Length + manifest.Length];
            Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
            Buffer.BlockCopy(manifest, 0, result, prefix.Length, manifest.Length);
            return result;
        }

        public static string Run(string executable, string directory, bool version)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = executable;
                process.StartInfo.WorkingDirectory = directory;
                // Every path argument is a constant basename in the fresh work directory.
                process.StartInfo.Arguments = version ? "version" :
                    "pkeyutl -verify -pubin -keyform DER -inkey anchor.der -rawin -in input.bin -sigfile signature.bin -provider default";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardInput = true;
                process.StartInfo.EnvironmentVariables.Clear();
                string windows=Directory.GetParent(Environment.SystemDirectory).FullName;
                process.StartInfo.EnvironmentVariables["SystemRoot"] = windows;
                process.StartInfo.EnvironmentVariables["WINDIR"] = windows;
                process.StartInfo.EnvironmentVariables["OPENSSL_CONF"] = Path.Combine(directory, "empty.cnf");
                process.StartInfo.EnvironmentVariables["OPENSSL_MODULES"] = directory;
                process.StartInfo.EnvironmentVariables["PATH"] = Environment.SystemDirectory;
                process.StartInfo.EnvironmentVariables["TEMP"] = directory;
                process.StartInfo.EnvironmentVariables["TMP"] = directory;
                bool started = false;
                try
                {
                    process.Start(); started = true; process.StandardInput.Close();
                    byte[] stdout = new byte[65537], stderr = new byte[65537];
                    int outCount = 0, errCount = 0;
                    bool outDone = false, errDone = false;
                    Task<int> outRead = process.StandardOutput.BaseStream.ReadAsync(stdout, 0, stdout.Length);
                    Task<int> errRead = process.StandardError.BaseStream.ReadAsync(stderr, 0, stderr.Length);
                    Stopwatch deadline = Stopwatch.StartNew();
                    while (!(outDone && errDone && process.HasExited))
                    {
                        if (deadline.ElapsedMilliseconds >= 5000)
                            throw new InvalidDataException("Signature verifier exceeded the fixed deadline.");
                        if (!outDone && outRead.IsCompleted)
                        {
                            int count = outRead.Result; outCount += count; outDone = count == 0;
                            if (outCount > 65536) throw new InvalidDataException("Signature verifier output exceeds bound.");
                            if (!outDone) outRead = process.StandardOutput.BaseStream.ReadAsync(stdout, outCount, stdout.Length - outCount);
                        }
                        if (!errDone && errRead.IsCompleted)
                        {
                            int count = errRead.Result; errCount += count; errDone = count == 0;
                            if (errCount > 65536) throw new InvalidDataException("Signature verifier output exceeds bound.");
                            if (!errDone) errRead = process.StandardError.BaseStream.ReadAsync(stderr, errCount, stderr.Length - errCount);
                        }
                        if (!(outDone && errDone && process.HasExited)) System.Threading.Thread.Sleep(5);
                    }
                    string output = new UTF8Encoding(false, true).GetString(stdout, 0, outCount).Trim();
                    if (process.ExitCode != 0 || errCount != 0)
                        throw new InvalidDataException("Detached package signature verification refused.");
                    if (version)
                    {
                        if (!System.Text.RegularExpressions.Regex.IsMatch(output, @"\AOpenSSL 3\.[0-9]+\.[0-9]+ [^\r\n]{1,200}\z"))
                            throw new InvalidDataException("Unsupported verifier version response.");
                    }
                    else if (output != "Signature Verified Successfully")
                        throw new InvalidDataException("Unexpected signature verifier response.");
                    return output;
                }
                finally
                {
                    if (started && !process.HasExited) { process.Kill(); process.WaitForExit(2000); }
                }
            }
        }
    }
}
