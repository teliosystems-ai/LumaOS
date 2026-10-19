using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Private live authority is never placed on the bulk build/archive drive.
    // NTFS, root-protected exact ACLs and held no-follow handles are mandatory.
    internal sealed class PrivateState : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Attributes {public int Length;public IntPtr Descriptor;public int Inherit;}
        [StructLayout(LayoutKind.Sequential)] private struct Information {
            public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
            public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
        }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateDirectory(string path,ref Attributes attributes);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out Information information);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool FlushFileBuffers(SafeFileHandle file);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool MoveFileEx(string source,string destination,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool GetVolumeInformation(string root,StringBuilder name,uint nameBytes,out uint serial,out uint maximum,out uint flags,StringBuilder format,uint formatBytes);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool GetDiskFreeSpaceEx(string path,out ulong available,out ulong total,out ulong free);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
        private readonly List<SafeFileHandle> ancestors=new List<SafeFileHandle>();
        private readonly List<Information> initial=new List<Information>();
        private readonly string directory,ownerSid,serviceSid;
        private FileStream mutex;
        private Action runtimeIntegrity;
        private HostedPhysicalTail physicalTail=HostedPhysicalTail.ForEnrollments(64,64);
        private PhysicalStage physicalStage;
        private sealed class PlannedFile {
            internal readonly long Bytes;internal readonly string Sha256;
            internal PlannedFile(byte[] bytes) {Bytes=bytes.Length;Sha256=Wire.Hash(bytes);}
        }
        private sealed class PhysicalStage {
            internal readonly ulong Sequence;internal readonly string Record;
            internal readonly HostedPhysicalTail Tail;
            internal readonly Dictionary<string,PlannedFile> Files=new Dictionary<string,PlannedFile>(StringComparer.Ordinal);
            internal PhysicalStage(JournalEntry entry,HostedPhysicalTail tail) {Sequence=entry.Sequence;Record=entry.RecordSha256;Tail=tail;}
        }
        internal void BindPhysicalHistory(JournalHistory history)
        {
            if(history==null || history.FileEnrollments==null) throw new SecurityException("Verified history is required for the physical terminal tail.");
            physicalTail=HostedPhysicalTail.ForEnrollments(history.FileEnrollments.ActiveCount,history.FileEnrollments.AbortReserveCredits);
            if(physicalStage!=null && history.Sequence>=physicalStage.Sequence) {
                if(history.Sequence==physicalStage.Sequence && history.Record!=physicalStage.Record) throw new SecurityException("Completed physical group differs from its exact signed journal candidate.");
                physicalStage=null;
            }
        }
        internal void BeginPhysicalStage(AuthorityIdentity identity,JournalHistory history,JournalEntry entry,DispatchTicket ticket,string pendingLeaf)
        {
            if(physicalStage!=null || (pendingLeaf!="pending.bin" && pendingLeaf!="abort.intent")) throw new SecurityException("Only one exact two-file journal stage may borrow physical tail capacity.");
            ticket.Matches(entry);HostedPhysicalTail tail=HostedJournalCapacity.ProjectedPhysicalTail(identity,history,entry);
            string dispatch="ticket-d-"+entry.RecordSha256+".bin";
            if(Exists(dispatch) || Exists(pendingLeaf)) throw new SecurityException("A physical journal group cannot adopt existing or partial files.");
            PhysicalStage stage=new PhysicalStage(entry,tail);stage.Files.Add(dispatch,new PlannedFile(ticket.Encode()));stage.Files.Add(pendingLeaf,new PlannedFile(entry.Bytes));
            physicalStage=stage;
            try {
                Capacity(null,null,0,false,true);
                RequireFree(checked(ticket.Encode().Length+entry.Bytes.Length+2*65536L+tail.AllocatedBytes));
            } catch {physicalStage=null;throw;}
        }
        internal void RequireCandidateTail(AuthorityIdentity identity,JournalHistory history,JournalEntry entry)
        {
            HostedPhysicalTail tail=HostedJournalCapacity.ProjectedPhysicalTail(identity,history,entry);
            Capacity(null,null,0,false,true,tail);if(tail.AllocatedBytes>0) RequireFree(tail.AllocatedBytes);
        }
        internal void RequireReadableTail()
        {Capacity(null,null,0,false,true,physicalTail);}
        internal void AttachRuntimeIntegrity(Action check) {if(check==null || runtimeIntegrity!=null) throw new SecurityException("Runtime integrity boundary cannot be absent or replaced.");runtimeIntegrity=check;check();}
        internal string DirectoryPath {get{return directory;}}
        private PrivateState(string directory,string ownerSid,string serviceSid) {this.directory=directory;this.ownerSid=ownerSid;this.serviceSid=serviceSid;}
        private static string Name(string value)
        {
            if(value==null || value.Length>80 || !System.Text.RegularExpressions.Regex.IsMatch(value,"\\A[a-z0-9][a-z0-9.-]*\\z") || value.Contains(".."))
                throw new InvalidDataException("Private state accepts fixed inert leaf names only.");return value;
        }
        private byte[] Descriptor()
        {
            RawSecurityDescriptor descriptor=new RawSecurityDescriptor("O:"+ownerSid+"G:"+ownerSid+"D:P(A;;GA;;;"+ownerSid+")(A;;GA;;;"+serviceSid+")");
            byte[] value=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(value,0);return value;
        }
        private static bool Same(Information a,Information b,bool contents)
        {
            return a.Attributes==b.Attributes && a.Volume==b.Volume && a.Links==b.Links && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow &&
                a.Creation.dwHighDateTime==b.Creation.dwHighDateTime && a.Creation.dwLowDateTime==b.Creation.dwLowDateTime &&
                (!contents || (a.SizeHigh==b.SizeHigh && a.SizeLow==b.SizeLow && a.Write.dwHighDateTime==b.Write.dwHighDateTime && a.Write.dwLowDateTime==b.Write.dwLowDateTime));
        }
        private Information Inspect(SafeFileHandle handle,bool isDirectory,bool requirePrivate)
        {
            Information information;if(!GetFileInformationByHandle(handle,out information)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(((information.Attributes&0x10)!=0)!=isDirectory || (information.Attributes&(0x200|0x400|0x800|0x1000|0x4000|0x40000|0x400000))!=0 || (!isDirectory && information.Links!=1))
                throw new SecurityException("Private state link/type/offline/cloud attributes refused.");
            if(requirePrivate) {
                IntPtr owner,group,dacl,sacl,descriptor;uint result=GetSecurityInfo(handle,1,7,out owner,out group,out dacl,out sacl,out descriptor);
                if(result!=0) throw new Win32Exception((int)result);
                try {
                    uint count=GetSecurityDescriptorLength(descriptor);if(count<20 || count>65536) throw new SecurityException("Private state ACL exceeds bound.");
                    byte[] bytes=new byte[count];Marshal.Copy(descriptor,bytes,0,(int)count);RawSecurityDescriptor security=new RawSecurityDescriptor(bytes,0);
                    if(security.Owner==null || security.Owner.Value!=ownerSid || (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
                        security.DiscretionaryAcl==null || security.DiscretionaryAcl.Count!=2) throw new SecurityException("Private state owner/protected DACL differs.");
                    HashSet<string> observed=new HashSet<string>(StringComparer.Ordinal);
                    foreach(GenericAce generic in security.DiscretionaryAcl) {
                        CommonAce ace=generic as CommonAce;
                        if(ace==null || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=AceFlags.None || ace.IsCallback ||
                            (ace.AccessMask!=0x10000000 && ace.AccessMask!=0x1f01ff) ||
                            (ace.SecurityIdentifier.Value!=ownerSid && ace.SecurityIdentifier.Value!=serviceSid) || !observed.Add(ace.SecurityIdentifier.Value))
                            throw new SecurityException("Private state contains broad, inherited or substituted ACL entries.");
                    }
                    if(!observed.Contains(ownerSid) || !observed.Contains(serviceSid)) throw new SecurityException("Private state lacks exact owner/service DACL.");
                } finally {LocalFree(descriptor);}
            }
            return information;
        }
        private SafeFileHandle Open(string path,bool isDirectory,uint access,uint share,uint disposition,bool privateAcl)
        {
            SafeFileHandle handle=CreateFile(path,access,share,IntPtr.Zero,disposition,0x00300000U|(isDirectory?0x02000000U:0x08000000U),IntPtr.Zero);
            if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
            try {Inspect(handle,isDirectory,privateAcl);return handle;} catch {handle.Dispose();throw;}
        }
        private void Pin(string path,bool privateAcl)
        {
            SafeFileHandle handle=Open(path,true,0x20081,3,3,privateAcl);ancestors.Add(handle);initial.Add(Inspect(handle,true,privateAcl));
        }
        private void Make(string path)
        {
            byte[] descriptor=Descriptor();GCHandle pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
            try {Attributes attributes=new Attributes {Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=pin.AddrOfPinnedObject(),Inherit=0};
                if(!CreateDirectory(path,ref attributes)) {int error=Marshal.GetLastWin32Error();if(error!=183) throw new Win32Exception(error);}
            } finally {pin.Free();}
        }
        private static void Ntfs(string root)
        {
            uint serial,maximum,flags;StringBuilder format=new StringBuilder(32),label=new StringBuilder(261);
            if(!GetVolumeInformation(root,label,261,out serial,out maximum,out flags,format,32)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(format.ToString()!="NTFS" || (flags&8)==0) throw new SecurityException("Private hosted authority requires native NTFS persistent ACLs.");
        }
        internal static PrivateState OpenFixed(string domain,bool create)
        {
            SecurityIdentifier service=FixedServiceIdentity.Require();PlatformCustodyProtocol.Index(domain);
            string common=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if(common.Length<4 || !String.Equals(Path.GetFullPath(common),common,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Fixed ProgramData path is not canonical.");
            string parent=Path.Combine(common,"LumaOS-HostedAuthority"),path=Path.Combine(parent,domain=="host-deployment"?"host":"content");
            PrivateState result=new PrivateState(path,"S-1-5-18",service.Value);
            try {
                string root=Path.GetPathRoot(path);Ntfs(root);string current=root;result.Pin(root,false);
                foreach(string part in common.Substring(root.Length).Split('\\')) {current=Path.Combine(current,part);result.Pin(current,false);}
                if(create) result.Make(parent);result.Pin(parent,true);if(create) result.Make(path);result.Pin(path,true);
                result.OpenMutex(create);result.Check();return result;
            } catch {result.Dispose();throw;}
        }
        private void OpenMutex(bool create)
        {
            string path=Path.Combine(directory,"authority.lock");
            if(!File.Exists(path)) {if(!create) throw new SecurityException("Existing private authority lock is missing; no implicit repair.");WriteNew("authority.lock",new byte[]{1});}
            SafeFileHandle handle=Open(path,false,0xc0020080,0,3,true);
            try {mutex=new FileStream(handle,FileAccess.ReadWrite,4096,false);} catch {handle.Dispose();throw;}
        }
        internal void Check()
        {
            FixedServiceIdentity.Require();
            if(runtimeIntegrity!=null) runtimeIntegrity();
            for(int index=0;index<ancestors.Count;index++) if(!Same(initial[index],Inspect(ancestors[index],true,index>=ancestors.Count-2),false))
                throw new SecurityException("Pinned private authority namespace changed.");
            if(mutex!=null) Inspect(mutex.SafeFileHandle,false,true);
        }
        internal bool Exists(string leaf) {Check();Name(leaf);return File.Exists(Path.Combine(directory,leaf));}
        internal byte[] Read(string leaf,int minimum,int maximum)
        {
            Check();Name(leaf);SafeFileHandle handle=Open(Path.Combine(directory,leaf),false,0x80020080,1,3,true);
            using(FileStream stream=new FileStream(handle,FileAccess.Read,4096,false)) {
                Information before=Inspect(stream.SafeFileHandle,false,true);
                if(stream.Length<minimum || stream.Length>maximum || maximum>Wire.MaximumFrame) throw new InvalidDataException("Private authority file exceeds fixed bound.");
                byte[] result=new byte[(int)stream.Length];int at=0;
                while(at<result.Length) {Check();int count=stream.Read(result,at,Math.Min(32768,result.Length-at));if(count==0) throw new EndOfStreamException("Private authority file truncated.");at+=count;}
                if(stream.ReadByte()!=-1 || !Same(before,Inspect(stream.SafeFileHandle,false,true),true)) throw new SecurityException("Private authority file changed during capture.");Check();return result;
            }
        }
        internal void WriteNew(string leaf,byte[] bytes)
        {
            Check();Name(leaf);Wire.Copy(bytes,1,Wire.MaximumFrame);
            if(physicalStage!=null) {
                PlannedFile planned;
                if(!physicalStage.Files.TryGetValue(leaf,out planned) || planned.Bytes!=bytes.Length || planned.Sha256!=Wire.Hash(bytes))
                    throw new SecurityException("Unrelated immutable write cannot consume a protected journal group.");
            }
            Capacity(null,null,bytes.Length,false,true);RequireFree(checked(bytes.Length+(physicalStage==null?physicalTail:physicalStage.Tail).AllocatedBytes));
            byte[] descriptor=Descriptor();GCHandle pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
            try {
                Attributes attributes=new Attributes {Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=pin.AddrOfPinnedObject(),Inherit=0};
                IntPtr native=Marshal.AllocHGlobal(attributes.Length);
                try {
                    Marshal.StructureToPtr(attributes,native,false);
                    SafeFileHandle handle=CreateFile(Path.Combine(directory,leaf),0xc0020080,0,native,1,0x80300000,IntPtr.Zero);
                    if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
                    using(FileStream stream=new FileStream(handle,FileAccess.ReadWrite,4096,false)) {
                        Inspect(stream.SafeFileHandle,false,true);HostedFileAllocation.ReserveEmpty(stream.SafeFileHandle,bytes.Length);
                        Capacity(leaf,stream.SafeFileHandle,0,false,true);Check();stream.Write(bytes,0,bytes.Length);stream.Flush(true);
                        Inspect(stream.SafeFileHandle,false,true);Capacity(leaf,stream.SafeFileHandle,0,false,true);
                    }
                } finally {Marshal.FreeHGlobal(native);}
            } finally {pin.Free();}
            FlushVolume();Check();
        }
        internal StagedPackage CapturePackage(string leaf,long bytes,string expectedSha256,Func<long,byte[]> next,Action check)
        {
            Name(leaf);if(!HostedStateCapacity.IsPackage(leaf) ||
                bytes<1024 || bytes>PackageInspector.MaximumArchiveBytes || next==null || check==null) throw new SecurityException("Closed package capture shape differs.");
            Wire.Bytes(expectedSha256,32,true);check();Check();if(physicalStage!=null) throw new SecurityException("Package capture cannot borrow a journal stage.");
            Capacity(null,null,bytes,true,true);RequireFree(checked(bytes+physicalTail.AllocatedBytes));
            byte[] descriptor=Descriptor();GCHandle pin=GCHandle.Alloc(descriptor,GCHandleType.Pinned);string destination=Path.Combine(directory,leaf);
            try {
                Attributes attributes=new Attributes {Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=pin.AddrOfPinnedObject(),Inherit=0};IntPtr native=Marshal.AllocHGlobal(attributes.Length);
                try {
                    Marshal.StructureToPtr(attributes,native,false);SafeFileHandle handle=CreateFile(destination,0xc0020080,0,native,1,0x80300000,IntPtr.Zero);
                    if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
                    using(FileStream output=new FileStream(handle,FileAccess.ReadWrite,32768,false)) using(SHA256 hash=SHA256.Create()) {
                        Inspect(output.SafeFileHandle,false,true);HostedFileAllocation.ReserveEmpty(output.SafeFileHandle,bytes);
                        Capacity(leaf,output.SafeFileHandle,0,true,true);check();Check();long at=0;
                        while(at<bytes) {
                            check();Check();byte[] part=next(at);
                            if(part==null || part.Length<1 || part.Length>32768 || part.Length>bytes-at) throw new InvalidDataException("Exact bounded package stream differs.");
                            check();output.Write(part,0,part.Length);hash.TransformBlock(part,0,part.Length,null,0);at+=part.Length;
                        }
                        hash.TransformFinalBlock(new byte[0],0,0);
                        if(Wire.Hex(hash.Hash)!=expectedSha256 || output.Length!=bytes) throw new SecurityException("Complete signed package SHA256 or length differs.");
                        check();output.Flush(true);Inspect(output.SafeFileHandle,false,true);Capacity(leaf,output.SafeFileHandle,0,true,true);
                    }
                } finally {Marshal.FreeHGlobal(native);}
            } finally {pin.Free();}
            FlushVolume();check();Check();return OpenPackage(leaf,bytes,expectedSha256,check);
        }
        internal StagedPackage OpenPackage(string leaf,long bytes,string expectedSha256,Action check)
        {
            Name(leaf);Wire.Bytes(expectedSha256,32,true);check();Check();SafeFileHandle handle=Open(Path.Combine(directory,leaf),false,0x80020080,1,3,true);
            FileStream source=null;
            try {
                source=new FileStream(handle,FileAccess.Read,32768,false);if(source.Length!=bytes || bytes<1024 || bytes>PackageInspector.MaximumArchiveBytes) throw new SecurityException("Staged package size differs.");
                using(SHA256 hash=SHA256.Create()) {byte[] block=new byte[32768];while(true) {check();Check();int count=source.Read(block,0,block.Length);if(count==0) break;hash.TransformBlock(block,0,count,null,0);}
                    hash.TransformFinalBlock(new byte[0],0,0);if(Wire.Hex(hash.Hash)!=expectedSha256) throw new SecurityException("Pinned full staged package hash differs.");}
                source.Position=0;check();return new StagedPackage(Path.Combine(directory,leaf),source,check);
            } catch {if(source!=null) source.Dispose();else handle.Dispose();throw;}
        }
        internal string[] Leaves()
        {
            Check();string[] names=Names();Capacity(null,null,0,false);Check();return names;
        }
        private string[] Names()
        {
            // Enumerate lazily: a damaged namespace must not allocate an
            // unbounded GetFiles/GetDirectories result before its count check.
            return HostedStateCapacity.BoundedNames(LeafNames());
        }
        private IEnumerable<string> LeafNames()
        {
            foreach(string path in System.IO.Directory.EnumerateFileSystemEntries(directory,"*",SearchOption.TopDirectoryOnly))
                yield return Path.GetFileName(path);
        }
        private void RequireFree(long bytes)
        {
            ulong available,total,free;
            if(bytes<1 || !GetDiskFreeSpaceEx(directory,out available,out total,out free) ||
                available<(ulong)bytes+(ulong)HostedStateCapacity.HostFreeReserveBytes+65536UL)
                throw new IOException("Native NTFS immutable-state allocation lacks the separate 1-GiB host reserve.");
        }
        private void Capacity(string activeLeaf,SafeFileHandle active,long appendBytes,bool package,bool reserve=false,HostedPhysicalTail exactTail=null)
        {
            Check();string[] names=Names();long metadata=0,packages=0,allocated=0;
            int newFiles=0;long newMetadata=0,newPackages=0,newAllocated=0;
            PhysicalStage stage=reserve && exactTail==null?physicalStage:null;
            if(stage!=null) foreach(PlannedFile value in stage.Files.Values) {newFiles++;newMetadata=checked(newMetadata+value.Bytes);newAllocated=checked(newAllocated+value.Bytes+65536);}
            List<SafeFileHandle> held=new List<SafeFileHandle>();
            try {
                foreach(string leaf in names) {
                    Check();SafeFileHandle handle;
                    if(leaf==activeLeaf) handle=active;
                    else if(leaf=="authority.lock" && mutex!=null) handle=mutex.SafeFileHandle;
                    else {handle=Open(Path.Combine(directory,leaf),false,0x80020080,1,3,true);held.Add(handle);}
                    Inspect(handle,false,true);HostedFileAllocation value=HostedFileAllocation.Observe(handle);
                    if(HostedStateCapacity.IsPackage(leaf)) {
                        if(value.LogicalBytes>PackageInspector.MaximumArchiveBytes) throw new SecurityException("Retained package exceeds its file bound.");
                        packages=checked(packages+value.LogicalBytes);
                    } else {
                        if(value.LogicalBytes>Wire.MaximumFrame) throw new SecurityException("Retained metadata exceeds its file bound.");
                        metadata=checked(metadata+value.LogicalBytes);
                    }
                    allocated=checked(allocated+value.AllocatedBytes);
                    PlannedFile planned;
                    if(stage!=null && stage.Files.TryGetValue(leaf,out planned)) {
                        if(value.LogicalBytes>planned.Bytes || value.AllocatedBytes<planned.Bytes) throw new SecurityException("Journal group file lost its exact preallocated bound.");
                        newFiles--;newMetadata=checked(newMetadata-value.LogicalBytes);newAllocated=checked(newAllocated-planned.Bytes-65536);
                    }
                }
                HostedStateCapacity.Require(names.Length,metadata,packages,allocated,0,package);
                if(reserve) {
                    if(stage==null && appendBytes>0) {newFiles=1;if(package) newPackages=appendBytes;else newMetadata=appendBytes;newAllocated=checked(appendBytes+65536);}
                    HostedStateCapacity.RequireProjected(names.Length,metadata,packages,allocated,newFiles,newMetadata,newPackages,newAllocated,exactTail??(stage==null?physicalTail:stage.Tail));
                } else if(appendBytes!=0) throw new SecurityException("A new private file requires physical-tail admission.");
                string[] after=Names();if(names.Length!=after.Length) throw new SecurityException("Private state inventory changed during capture.");
                for(int index=0;index<names.Length;index++) if(names[index]!=after[index]) throw new SecurityException("Private state inventory changed during capture.");
                // The exclusive writer mutex and retained file handles keep
                // ordinary competing writers/renames out; root remains trusted.
                Check();
            } finally {foreach(SafeFileHandle handle in held) handle.Dispose();}
        }
        internal void Publish(string source,string destination)
        {
            Check();Name(source);Name(destination);Read(source,1,Wire.MaximumFrame);
            if(!MoveFileEx(Path.Combine(directory,source),Path.Combine(directory,destination),8)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(physicalStage!=null && physicalStage.Files.ContainsKey(source)) {
                PlannedFile moved=physicalStage.Files[source];physicalStage.Files.Remove(source);physicalStage.Files.Add(destination,moved);
            }
            FlushVolume();Read(destination,1,Wire.MaximumFrame);Check();
        }
        internal void RemovePublishedDuplicate(string leaf,string expectedSha256)
        {
            Check();Name(leaf);if(Wire.Hash(Read(leaf,1,Wire.MaximumFrame))!=expectedSha256) throw new SecurityException("Pending duplicate differs from actual published record.");
            // Parent and file are private, single-link and no-follow checked.
            // No caller pathname, wildcard, directory or authority reset exists.
            File.Delete(Path.Combine(directory,leaf));FlushVolume();Check();
        }
        private void FlushVolume()
        {
            FixedServiceIdentity.Require();string volume=@"\\.\"+Path.GetPathRoot(directory).Substring(0,2);
            using(SafeFileHandle handle=CreateFile(volume,0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
                if(handle.IsInvalid || !FlushFileBuffers(handle)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Private journal metadata durability unconfirmed; preserve pending data.");
            }
        }
        public void Dispose() {if(mutex!=null){mutex.Dispose();mutex=null;}for(int index=ancestors.Count-1;index>=0;index--) ancestors[index].Dispose();ancestors.Clear();initial.Clear();}
    }

    internal sealed class StagedPackage : IDisposable
    {
        internal readonly string Path;private readonly FileStream source;private readonly Action check;
        internal StagedPackage(string path,FileStream source,Action check) {Path=path;this.source=source;this.check=check;}
        internal Stream Rewind() {check();source.Position=0;return source;}
        public void Dispose() {source.Dispose();}
    }

    internal sealed class DurableJournal
    {
        private readonly PrivateState state;private readonly AuthorityIdentity identity;private readonly HardwareKey key;private readonly FixedNvAuthority nv;
        private int currentDispatchAttempts;
        internal DurableJournal(PrivateState state,AuthorityIdentity identity,HardwareKey key,FixedNvAuthority nv) {this.state=state;this.identity=identity;this.key=key;this.nv=nv;}
        internal JournalHistory Read(Action check)
        {
            if(check==null) throw new ArgumentNullException("check");check();
            List<byte[]> records=new List<byte[]>();
            foreach(string leaf in state.Leaves()) {
                check();
                if(leaf.StartsWith("record-",StringComparison.Ordinal)) {
                    string expected="record-"+(records.Count+1).ToString("D4",System.Globalization.CultureInfo.InvariantCulture)+".bin";
                    if(leaf!=expected) throw new SecurityException("Private journal contains a gap or unknown record name.");records.Add(state.Read(leaf,1,20000));
                } else if(leaf!="authority.lock" && leaf!="identity.bin" && leaf!="identity.pending" && leaf!="commission.intent" && leaf!="pending.bin" && leaf!="abort.intent" && !leaf.StartsWith("ticket-",StringComparison.Ordinal))
                    throw new SecurityException("Unknown private hosted-authority state file.");
            }
            JournalHistory history=JournalHistory.Replay(identity,records.ToArray(),check);
            state.BindPhysicalHistory(history);
            currentDispatchAttempts=HostedDispatchInventory.Validate(identity,history,state.Leaves(),delegate(string leaf) {check();return state.Read(leaf,1,20000);});
            check();return history;
        }
        internal JournalHistory Recover(Action check)
        {
            if(state.Exists("abort.intent")) throw new SecurityException("A staged abort requires its exact fresh reviewed recover-abort action; no generic continuation.");
            check();JournalHistory history=Read(check);byte[] pending=state.Exists("pending.bin")?state.Read("pending.bin",1,20000):null;
            RecoveryPhase phase=history.Reconcile(identity,pending,nv.ReadHead());
            if(phase==RecoveryPhase.PreparedNotExtended) {
                throw new SecurityException("Prepared TPM write has uncertain dispatch state. Pending data is retained; no extend, retry or abort is permitted without independent hardware session-drain proof.");
            }
            if(phase==RecoveryPhase.ExtendedNotPublished) {
                JournalEntry entry=JournalEntry.Decode(identity,pending);check();state.Publish("pending.bin","record-"+entry.Sequence.ToString("D4",System.Globalization.CultureInfo.InvariantCulture)+".bin");
            } else if(phase==RecoveryPhase.AlreadyPublished) {check();state.RemovePublishedDuplicate("pending.bin",Wire.Hash(pending));}
            check();history=Read(check);history.Reconcile(identity,null,nv.ReadHead());check();return history;
        }
        internal JournalEntry Append(JournalKind kind,string actorSid,byte[] payload,Action check)
        {
            check();
            if(state.Exists("pending.bin") || state.Exists("abort.intent")) throw new SecurityException("An interrupted authority write requires its own exact reviewed recovery command.");
            JournalHistory history=Read(check);history.Reconcile(identity,null,nv.ReadHead());check();
            JournalEntry entry=JournalEntry.Prepare(identity,checked(history.Sequence+1),kind,history.Head,history.Record,actorSid,payload);
            entry=entry.Signed(identity,key.Sign(entry.SigningInput));DispatchTicket ticket=PrepareDispatch(entry,check);check();state.WriteNew("pending.bin",entry.Bytes);
            DispatchFirst(entry,ticket,check);check();
            state.Publish("pending.bin","record-"+entry.Sequence.ToString("D4",System.Globalization.CultureInfo.InvariantCulture)+".bin");
            JournalHistory completed=Read(check);completed.Reconcile(identity,null,nv.ReadHead());check();return entry;
        }
        private static string DispatchLeaf(string digest) {Wire.Bytes(digest,32,true);return "ticket-d-"+digest+".bin";}
        private static string AbandonedLeaf(string digest) {Wire.Bytes(digest,32,true);return "ticket-a-"+digest+".bin";}
        internal DispatchTicket PrepareDispatch(JournalEntry entry,Action check,bool replacement=false)
        {
            check();JournalHistory history=Read(check);if(history.Sequence!=0) history.Reconcile(identity,null,nv.ReadHead());
            HostedDispatchInventory.RequireNext(currentDispatchAttempts,replacement);
            return HostedJournalCapacity.BeforeStage(identity,history,entry,delegate {
                check();byte[] input=DispatchTicket.SigningInput(identity,entry,HostedHostResources.BootCreation(),nv.ReadEpoch());
                DispatchTicket ticket=DispatchTicket.Signed(identity,input,key.Sign(input));check();
                state.BeginPhysicalStage(identity,history,entry,ticket,replacement?"abort.intent":"pending.bin");
                state.WriteNew(DispatchLeaf(entry.RecordSha256),ticket.Encode());check();return ticket;
            });
        }
        internal void DispatchFirst(JournalEntry entry,DispatchTicket ticket,Action check)
        {
            check();JournalHistory capacity=Read(check);capacity.Reconcile(identity,null,nv.ReadHead());HostedJournalCapacity.Require(identity,capacity,entry);
            ticket.Matches(entry);Action dispatch=delegate {
                check();if(HostedHostResources.BootCreation()!=ticket.Boot || !nv.ReadEpoch().SameEpoch(ticket.Epoch)) throw new SecurityException("Host/TPM epoch changed after durable dispatch preparation; preserve the pending fence.");
            };
            dispatch();if(!Wire.Equal(state.Read("pending.bin",1,20000),entry.Bytes) || !Wire.Equal(state.Read(DispatchLeaf(entry.RecordSha256),1,2048),ticket.Encode()))
                throw new SecurityException("Exact first-dispatch record or signed metadata changed.");
            state.RequireCandidateTail(identity,capacity,entry);dispatch();
            nv.Extend(entry.PreviousHead,entry.RecordSha256,dispatch);dispatch();
        }
        internal byte[] ReviewAbort(Action check)
        {return ReviewAbort(check,false);}
        private NvAbortEvent AbortedEvent(JournalEntry replacement)
        {
            return replacement.Kind==JournalKind.Commission?CommissionIntent.Decode(state.Read("commission.intent",1,4096)).RecoveredGenesis(identity,replacement.Payload):NvAbortEvent.Decode(identity,replacement.Payload);
        }
        internal byte[] ReviewAbort(Action check,bool genesis)
        {
            check();JournalHistory history=Read(check);JournalEntry old;
            if(state.Exists("abort.intent")) {
                JournalEntry staged=JournalEntry.Decode(identity,state.Read("abort.intent",1,20000));NvAbortEvent value=AbortedEvent(staged);value.Matches(staged);
                string leaf=state.Exists("pending.bin")?"pending.bin":AbandonedLeaf(value.Abandoned.RecordSha256);old=JournalEntry.Decode(identity,state.Read(leaf,1,20000));value.Abandoned.Matches(old);
            } else {old=JournalEntry.Decode(identity,state.Read("pending.bin",1,20000));}
            if((old.Kind==JournalKind.Commission)!=genesis || old.Sequence!=history.Sequence+1 || old.PreviousHead!=history.Head || old.PreviousRecord!=history.Record || nv.ReadHead()!=history.Head)
                throw new SecurityException("Abort needs the exact previous-head pending event in its separate commissioning or post-commission purpose; exact-next writes use finalize recovery, never abort.");
            if(genesis) CommissionIntent.Decode(state.Read("commission.intent",1,4096)).ValidateGenesis(identity,old.Payload);
            DispatchTicket ticket=DispatchTicket.Decode(identity,state.Read(DispatchLeaf(old.RecordSha256),1,2048));ticket.Matches(old);
            ulong boot=HostedHostResources.BootCreation();TpmEpoch epoch=nv.ReadEpoch();epoch.RequireResetSince(ticket.Epoch,ticket.Boot,boot);check();
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-nv-abort-review-v1")) {
                writer.Fixed(Wire.Bytes(old.RecordSha256,32,true),32);writer.Fixed(Wire.HashBytes(ticket.Encode()),32);writer.Fixed(Wire.Bytes(history.Head,32,history.Sequence!=0),32);
                writer.U64(boot);writer.U32(epoch.Reset);writer.U32(epoch.Restart);writer.U8(state.Exists("abort.intent")?(byte)1:(byte)0);
                if(state.Exists("abort.intent")) writer.Fixed(Wire.HashBytes(state.Read("abort.intent",1,20000)),32);return writer.Bytes();
            }
        }
        internal JournalHistory Abort(byte[] reviewed,Action check)
        {return Abort(reviewed,check,false);}
        internal JournalHistory Abort(byte[] reviewed,Action check,bool genesis)
        {
            check();if(!Wire.Equal(reviewed,ReviewAbort(check,genesis))) throw new SecurityException("Reviewed exact abort event, head or independent kernel/TPM epoch changed.");
            JournalHistory history=Read(check);JournalEntry old,prepared=null;
            if(state.Exists("abort.intent")) {
                prepared=JournalEntry.Decode(identity,state.Read("abort.intent",1,20000));NvAbortEvent prior=AbortedEvent(prepared);prior.Matches(prepared);
                old=JournalEntry.Decode(identity,state.Read(state.Exists("pending.bin")?"pending.bin":AbandonedLeaf(prior.Abandoned.RecordSha256),1,20000));prior.Abandoned.Matches(old);
                HostedJournalCapacity.Require(identity,history,prepared);check();
                DispatchTicket dispatch=DispatchTicket.Decode(identity,state.Read(DispatchLeaf(prepared.RecordSha256),1,2048));dispatch.Matches(prepared);
                if(dispatch.Boot!=HostedHostResources.BootCreation() || !dispatch.Epoch.SameEpoch(nv.ReadEpoch())) {
                    // abort.intent has never been placed in pending.bin, so
                    // no dispatch of this replacement was possible. Retain it
                    // as unused evidence before preparing a fresh event.
                    if(!state.Exists("pending.bin")) {check();state.WriteNew("pending.bin",old.Bytes);}
                    check();state.Publish("abort.intent","ticket-u-"+prepared.RecordSha256+".bin");prepared=null;
                }
            } else old=JournalEntry.Decode(identity,state.Read("pending.bin",1,20000));
            if(prepared==null) {
                DispatchTicket abandoned=DispatchTicket.Decode(identity,state.Read(DispatchLeaf(old.RecordSha256),1,2048));abandoned.Matches(old);
                NvAbortEvent value=new NvAbortEvent(abandoned,HostedHostResources.BootCreation(),nv.ReadEpoch(),Wire.Random(32));
                byte[] payload=genesis?CommissionIntent.Decode(state.Read("commission.intent",1,4096)).RecoveredGenesisPayload(identity,value):value.Encode();
                prepared=JournalEntry.Prepare(identity,old.Sequence,genesis?JournalKind.Commission:JournalKind.NvWriteAborted,history.Head,history.Record,identity.FirstAdminSid,payload);prepared=prepared.Signed(identity,key.Sign(prepared.SigningInput));
                PrepareDispatch(prepared,check,true);check();state.WriteNew("abort.intent",prepared.Bytes);
            }
            // The replacement remains non-dispatched while abort.intent
            // exists. The atomic rename below is its one first-dispatch gate.
            HostedJournalCapacity.Require(identity,history,prepared);check();
            if(state.Exists("pending.bin")) {
                if(!Wire.Equal(state.Read("pending.bin",1,20000),old.Bytes)) throw new SecurityException("Abandoned pending event changed.");
                string archive=AbandonedLeaf(old.RecordSha256);check();
                if(state.Exists(archive)) {if(!Wire.Equal(state.Read(archive,1,20000),old.Bytes)) throw new SecurityException("Retained abandoned record differs.");state.RemovePublishedDuplicate("pending.bin",old.RecordSha256);}
                else state.Publish("pending.bin",archive);
            }
            check();state.Publish("abort.intent","pending.bin");
            DispatchTicket current=DispatchTicket.Decode(identity,state.Read(DispatchLeaf(prepared.RecordSha256),1,2048));DispatchFirst(prepared,current,check);return Recover(check);
        }
    }
}
