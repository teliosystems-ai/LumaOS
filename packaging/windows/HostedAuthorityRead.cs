using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Stable reviewed input only. Neither this record nor prior source approval
    // grants a read: a new original-client review and live 30s session are required.
    public sealed class EnrolledReadIntent
    {
        public const int MaximumBytes=1048576;
        public string Installation {get;private set;}public string Owner {get;private set;}public string Root {get;private set;}
        public string RelativePath {get;private set;}public string Sha256 {get;private set;}public int Bytes {get;private set;}
        public string Path {get{return System.IO.Path.Combine(Root,RelativePath);}}
        public EnrolledReadIntent(string installation,string owner,string root,string relative,int bytes,string sha256) {
            Wire.Bytes(installation,32,true);Wire.Sid(owner);Wire.Bytes(sha256,32,false);
            if(bytes<1 || bytes>MaximumBytes || root==null || root.Length<4 || root.EndsWith("\\",StringComparison.Ordinal) || relative==null || relative.Length==0 || System.IO.Path.IsPathRooted(relative)) throw new SecurityException("Read intent requires one exact nonempty bounded file under a named directory.");
            ValidateSelectedPath(root);string full=System.IO.Path.Combine(root,relative);ValidateSelectedPath(full);
            if(!String.Equals(full,root+"\\"+relative,StringComparison.Ordinal) || !String.Equals(System.IO.Path.GetFullPath(full),full,StringComparison.Ordinal) || full.Substring(3).Split('\\').Length>32) throw new SecurityException("Read intent changed the exact canonical path or exceeded its held ancestor bound.");
            Installation=installation;Owner=owner;Root=root;RelativePath=relative;Bytes=bytes;Sha256=sha256;
        }
        private static void ValidateSelectedPath(string path) {
            // Canonical records must remain decodable when a source volume is
            // absent. Actual local NTFS is checked only by the live read lease.
            if(String.IsNullOrEmpty(path) || path.Length>240 || !Regex.IsMatch(path,"\\A[A-Za-z]:\\\\") || path.IndexOf('/')>=0 || path.IndexOf(':',2)>=0 || !String.Equals(path,System.IO.Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Read requires bounded canonical absolute local path syntax.");
            foreach(string part in path.Substring(3).Split('\\')) if(part.Length==0 || part=="." || part==".." || part.EndsWith(".",StringComparison.Ordinal) || part.EndsWith(" ",StringComparison.Ordinal) || part.IndexOf('~')>=0 || !Regex.IsMatch(part,"\\A[A-Za-z0-9_. -]+\\z") || Regex.IsMatch(part,"\\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\.|\\z)",RegexOptions.IgnoreCase)) throw new InvalidDataException("Read path has an unsupported or ambiguous component.");
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-intent-v1")) {writer.Text("read-exact-file",32);writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.Text(Owner,184);writer.Text(Root,240);writer.Text(RelativePath,240);writer.U32((uint)Bytes);writer.Fixed(Wire.Bytes(Sha256,32,false),32);return writer.Bytes();}}
        public static EnrolledReadIntent Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-read-intent-v1")) {
            if(reader.Text(32)!="read-exact-file") throw new SecurityException("Ingestion cannot be used for indexing, organization, writes or another read purpose.");
            string installation=Wire.Hex(reader.Fixed(32)),owner=reader.Text(184),root=reader.Text(240),relative=reader.Text(240);uint count=reader.U32();string sha=Wire.Hex(reader.Fixed(32));reader.End();
            if(count>MaximumBytes) throw new SecurityException("Read intent exceeds its closed byte budget.");return new EnrolledReadIntent(installation,owner,root,relative,(int)count,sha);
        }}
        public void Match(AuthorityIdentity identity,string actualOwner) {
            if(identity==null || identity.Domain!="host-deployment" || Installation!=identity.Installation || Owner!=identity.FirstAdminSid || actualOwner!=identity.FirstAdminSid) throw new SecurityException("Only the actual separately commissioned first Admin owns this ephemeral host read; no ordinary-user or Linux principal is inferred.");
        }
        internal void ValidateSnapshot(byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-read-object-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(Encode())) throw new SecurityException("Read object belongs to another exact intent.");int count=reader.U8();
                if(count!=Path.Substring(3).Split('\\').Length+1 || count<2 || count>33) throw new SecurityException("Read object ancestor count differs from exact selected path.");
                for(int index=0;index<count;index++) {reader.U32();uint high=reader.U32(),low=reader.U32(),attributes=reader.U32();reader.U32();reader.U32();Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);
                    if((high==0 && low==0) || ((attributes&0x10)!=0)!=(index<count-1) || (attributes&(0x400U|0x1000U|0x40000U|0x80000U|0x100000U|0x400000U))!=0) throw new SecurityException("Read object contains an invalid identity, linked/cloud attribute or wrong type.");
                }
                if(reader.U32()!=0 || reader.U32()!=Bytes) throw new SecurityException("Observed exact file bytes differ.");reader.U32();reader.U32();reader.End();
            }
        }
    }

    // This gate binds a single confirmed review to one exact source object. It
    // is internal session state, never a caller-supplied grant or persistent enrollment.
    internal sealed class EnrolledReadDelivery
    {
        private readonly EnrolledReadIntent intent;private readonly string review,source;private long delivered;private bool begun,completed;
        internal EnrolledReadDelivery(EnrolledReadIntent intent,string review,string source) {if(intent==null) throw new ArgumentNullException("intent");Wire.Bytes(review,32,true);Wire.Bytes(source,32,true);this.intent=intent;this.review=review;this.source=source;}
        internal string Review {get{return review;}}internal string Source {get{return source;}}internal long Delivered {get{return delivered;}}
        internal void Begin(string exactIntent,string exactSource) {if(begun || completed || exactIntent!=Wire.Hash(intent.Encode()) || exactSource!=source) throw new SecurityException("Read source, reviewed object or one-use admission changed.");begun=true;}
        internal byte[] Chunk(byte[] data,int offset) {
            if(!begun || completed || offset!=delivered || data==null || data.Length!=intent.Bytes || offset<0 || offset>=data.Length) throw new SecurityException("Read delivery changed state, source bytes or exact cumulative offset.");
            using(SHA256 hash=SHA256.Create()) if(Wire.Hex(hash.ComputeHash(data))!=intent.Sha256) throw new SecurityException("Read delivery substituted bytes behind its reviewed full source hash.");
            int count=Math.Min(32768,data.Length-offset);byte[] part=new byte[count];Buffer.BlockCopy(data,offset,part,0,count);
            try {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-chunk-v1")) {writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(source,32,true),32);writer.U32((uint)offset);writer.Blob(part,32768);return writer.Bytes();}}finally {Array.Clear(part,0,part.Length);}
        }
        internal void Acknowledge(byte[] bytes,byte[] data) {
            if(!begun || completed || data==null || data.Length!=intent.Bytes || delivered>=data.Length) throw new SecurityException("Read acknowledgement has no live admitted delivery.");
            long next=delivered+Math.Min(32768,data.Length-(int)delivered);using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-read-ack-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=source || reader.U32()!=next) throw new SecurityException("Read acknowledgement substituted review, source or cumulative bytes.");
                byte[] expected;using(SHA256 hash=SHA256.Create()) expected=hash.ComputeHash(data,0,(int)next);if(!Wire.Equal(reader.Fixed(32),expected)) throw new SecurityException("Original client did not acknowledge the exact delivered prefix.");reader.End();
            }delivered=next;
        }
        internal byte[] Complete() {
            if(!begun || completed || delivered!=intent.Bytes) throw new SecurityException("Partial or replayed read cannot report complete delivery.");completed=true;
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-completed-v1")) {
                writer.Fixed(Wire.HashBytes(intent.Encode()),32);writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(source,32,true),32);writer.U32((uint)delivered);writer.Fixed(Wire.Bytes(intent.Sha256,32,false),32);
                // Read-only; no persistent enrollment, content publication, Linux
                // identity/grant, write/effect execution or production qualification.
                writer.U8(1);for(int index=0;index<6;index++) writer.U8(0);return writer.Bytes();
            }
        }
    }

    internal sealed class EnrolledReadSource : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [StructLayout(LayoutKind.Sequential)] private struct Luid {public uint Low;public int High;}
        [StructLayout(LayoutKind.Sequential)] private struct Statistics {public Luid TokenId,AuthenticationId;public long Expiration;public uint Type,Level,Charged,Available,Groups,Privileges;public Luid Modified;}
        [StructLayout(LayoutKind.Sequential)] private struct Mapping {public uint Read,Write,Execute,All;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out Information information);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetFileType(SafeFileHandle file);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint count,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file,StringBuilder name,uint nameCount,out uint serial,out uint maximum,out uint flags,StringBuilder format,uint formatCount);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CancelIoEx(SafeFileHandle file,IntPtr overlapped);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool DuplicateToken(SafeAccessTokenHandle source,int level,out SafeAccessTokenHandle duplicate);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr data,uint size,out uint count);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool LookupPrivilegeValue(string system,string name,out Luid value);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool AccessCheck(IntPtr descriptor,SafeAccessTokenHandle token,uint desired,ref Mapping mapping,IntPtr privileges,ref uint privilegeCount,out uint granted,out bool allowed);
        private sealed class Node {internal SafeFileHandle Handle;internal Information Initial;internal bool Directory;internal byte[] Security;}
        private readonly List<Node> nodes=new List<Node>();private readonly EnrolledReadIntent intent;private readonly Action original;
        private readonly SafeAccessTokenHandle primary;private SafeAccessTokenHandle access;private readonly Statistics initialToken;private FileStream stream;
        internal EnrolledReadSource(EnrolledReadIntent intent,SafeAccessTokenHandle primary,Action original) {
            if(intent==null || primary==null || primary.IsInvalid || original==null) throw new ArgumentNullException("read source");this.intent=intent;this.primary=primary;this.original=original;
            try {
                original();DriveType drive=new DriveInfo(System.IO.Path.GetPathRoot(intent.Path)).DriveType;if(drive!=DriveType.Fixed && drive!=DriveType.Removable) throw new SecurityException("Actual source must be fixed/removable local storage, never a mapped network volume.");initialToken=TokenStatistics(primary);RequireToken();if(!DuplicateToken(primary,2,out access)) throw new Win32Exception(Marshal.GetLastWin32Error());
                string current=intent.Path.Substring(0,3);Open(current,true);string[] pieces=intent.Path.Substring(3).Split('\\');
                for(int index=0;index<pieces.Length-1;index++) {current=System.IO.Path.Combine(current,pieces[index]);Open(current,true);}SafeFileHandle file=Open(intent.Path,false);
                stream=new FileStream(file,FileAccess.Read,32768,true);if(stream.Length!=intent.Bytes) throw new SecurityException("Actual enrolled object length differs from exact reviewed bytes.");Check();
            }catch {Dispose();throw;}
        }
        private static IntPtr TokenInformation(SafeAccessTokenHandle token,int kind,int bound) {
            uint count;GetTokenInformation(token,kind,IntPtr.Zero,0,out count);if(count<1 || count>bound) throw new SecurityException("Read token information exceeds bound.");IntPtr data=Marshal.AllocHGlobal((int)count);
            if(!GetTokenInformation(token,kind,data,count,out count)) {Marshal.FreeHGlobal(data);throw new Win32Exception(Marshal.GetLastWin32Error());}return data;
        }
        private static Statistics TokenStatistics(SafeAccessTokenHandle token) {IntPtr data=TokenInformation(token,10,256);try {return (Statistics)Marshal.PtrToStructure(data,typeof(Statistics));}finally {Marshal.FreeHGlobal(data);}}
        private static bool Same(Luid left,Luid right) {return left.Low==right.Low && left.High==right.High;}
        private void RequireToken() {
            Statistics now=TokenStatistics(primary);if(now.Type!=1 || !Same(now.TokenId,initialToken.TokenId) || !Same(now.AuthenticationId,initialToken.AuthenticationId) || !Same(now.Modified,initialToken.Modified)) throw new SecurityException("Actual original read token changed.");
            using(WindowsIdentity identity=new WindowsIdentity(primary.DangerousGetHandle())) if(identity.User==null || identity.User.Value!=intent.Owner || !identity.IsAuthenticated) throw new SecurityException("Source is not opened for its actual original Windows owner.");
            IntPtr privileges=TokenInformation(primary,3,8192);try {
                uint count=unchecked((uint)Marshal.ReadInt32(privileges));if(count>128) throw new SecurityException("Read privilege set exceeds bound.");
                foreach(string name in new string[]{"SeDebugPrivilege","SeBackupPrivilege","SeRestorePrivilege","SeTakeOwnershipPrivilege","SeSecurityPrivilege"}) {
                    Luid blocked;if(!LookupPrivilegeValue(null,name,out blocked)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    for(int index=0;index<count;index++) {IntPtr entry=IntPtr.Add(privileges,4+index*12);if(unchecked((uint)Marshal.ReadInt32(entry))==blocked.Low && Marshal.ReadInt32(entry,4)==blocked.High && (Marshal.ReadInt32(entry,8)&2)!=0) throw new SecurityException("Source read cannot use enabled ACL-bypass privileges.");}
                }
            }finally {Marshal.FreeHGlobal(privileges);}
        }
        private static Information Inspect(SafeFileHandle file,bool directory,string path) {
            Information value;if(GetFileType(file)!=1 || !GetFileInformationByHandle(file,out value)) throw new IOException("Read source requires an actual local disk object.");
            if(((value.Attributes&0x10)!=0)!=directory || (value.Attributes&(0x400U|0x1000U|0x40000U|0x80000U|0x100000U|0x400000U))!=0 || !directory && value.Links!=1) throw new SecurityException("Read source is linked, offline, recalled, cloud-backed or the wrong type.");
            StringBuilder final=new StringBuilder(512);uint count=GetFinalPathNameByHandle(file,final,512,0);if(count==0 || count>=512 || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Read handle selected another exact path.");
            StringBuilder format=new StringBuilder(32),name=new StringBuilder(256);uint serial,maximum,flags;if(!GetVolumeInformationByHandleW(file,name,256,out serial,out maximum,out flags,format,32) || format.ToString()!="NTFS" || serial!=value.Volume) throw new SecurityException("Read source requires observed native NTFS, not a guessed drive format.");return value;
        }
        private byte[] Security(SafeFileHandle file,bool directory,string path) {
            IntPtr owner,group,dacl,sacl,descriptor;uint status=GetSecurityInfo(file,1,7,out owner,out group,out dacl,out sacl,out descriptor);if(status!=0) throw new Win32Exception((int)status);
            try {
                uint count=GetSecurityDescriptorLength(descriptor);if(count<20 || count>65536 || dacl==IntPtr.Zero || owner==IntPtr.Zero) throw new SecurityException("Read source has unbounded or unconstrained security.");
                if(!directory && new SecurityIdentifier(owner).Value!=intent.Owner) throw new SecurityException("Actual source object owner is not the enrolled original SID.");
                uint desired=directory?0x200a0U:0x120089U;Mapping mapping=new Mapping {Read=0x120089,Write=0x120116,Execute=0x1200a0,All=0x1f01ff};uint length=8192,granted;bool allowed;IntPtr privileges=Marshal.AllocHGlobal((int)length);
                try {if(!AccessCheck(descriptor,access,desired,ref mapping,privileges,ref length,out granted,out allowed)) throw new Win32Exception(Marshal.GetLastWin32Error());if(!allowed || (granted&desired)!=desired) throw new UnauthorizedAccessException("Actual original token ACL denies exact "+(directory?"ancestor traversal":"source read")+" at "+path+"; requested "+desired.ToString("x",CultureInfo.InvariantCulture)+", granted "+granted.ToString("x",CultureInfo.InvariantCulture)+".");}finally {Marshal.FreeHGlobal(privileges);}
                byte[] bytes=new byte[count];Marshal.Copy(descriptor,bytes,0,(int)count);return bytes;
            }finally {LocalFree(descriptor);}
        }
        private SafeFileHandle Open(string path,bool directory) {
            original();RequireToken();SafeFileHandle handle=null;
            // Only this bounded OS open is impersonated. Custody/UTC/session
            // checks run outside impersonation; System never opens source data.
            int error=0;SafeFileHandle metadata=null;WindowsIdentity.RunImpersonated(access,delegate {metadata=CreateFile(path,0x20080U,directory?3U:1U,IntPtr.Zero,3,directory?0x02300000U:0x00300000U,IntPtr.Zero);if(metadata.IsInvalid) error=Marshal.GetLastWin32Error();});
            try {if(metadata==null || metadata.IsInvalid) throw new Win32Exception(error);Information before=Inspect(metadata,directory,path);byte[] beforeSecurity=Security(metadata,directory,path);original();
                WindowsIdentity.RunImpersonated(access,delegate {handle=CreateFile(path,directory?0x200a0U:0x80020080U,directory?3U:1U,IntPtr.Zero,3,directory?0x02300000U:0x48300000U,IntPtr.Zero);if(handle.IsInvalid) error=Marshal.GetLastWin32Error();});
                if(handle==null || handle.IsInvalid) throw new Win32Exception(error);Information information=Inspect(handle,directory,path);byte[] security=Security(handle,directory,path);
                if(!Same(before,information,directory) || !Wire.Equal(beforeSecurity,security)) throw new SecurityException("Read source changed between metadata-only inspection and original-token data pin.");
                nodes.Add(new Node {Handle=handle,Initial=information,Directory=directory,Security=security});original();return handle;
            }catch {if(handle!=null && !nodes.Exists(delegate(Node node) {return Object.ReferenceEquals(node.Handle,handle);})) handle.Dispose();throw;}finally {if(metadata!=null) metadata.Dispose();}
        }
        private static bool Same(Information left,Information right,bool directory) {return left.Attributes==right.Attributes && left.Volume==right.Volume && left.IndexHigh==right.IndexHigh && left.IndexLow==right.IndexLow && left.Creation.dwHighDateTime==right.Creation.dwHighDateTime && left.Creation.dwLowDateTime==right.Creation.dwLowDateTime &&
            (directory || left.Links==right.Links && left.SizeHigh==right.SizeHigh && left.SizeLow==right.SizeLow && left.Write.dwHighDateTime==right.Write.dwHighDateTime && left.Write.dwLowDateTime==right.Write.dwLowDateTime);}
        internal void Check() {
            original();RequireToken();if(stream==null) throw new ObjectDisposedException("EnrolledReadSource");string current=intent.Path.Substring(0,3);string[] pieces=intent.Path.Substring(3).Split('\\');
            for(int index=0;index<nodes.Count;index++) {if(index>0) current=System.IO.Path.Combine(current,pieces[index-1]);Node node=nodes[index];if(!Same(node.Initial,Inspect(node.Handle,node.Directory,current),node.Directory) || !Wire.Equal(node.Security,Security(node.Handle,node.Directory,current))) throw new SecurityException("Read source identity, immutable bytes metadata or actual owner/ACL changed.");if(index%4==0) original();}original();
        }
        internal byte[] Snapshot() {
            Check();using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-object-v1")) {writer.Fixed(Wire.HashBytes(intent.Encode()),32);writer.U8((byte)nodes.Count);
                foreach(Node node in nodes) {Information value=node.Initial;writer.U32(value.Volume);writer.U32(value.IndexHigh);writer.U32(value.IndexLow);writer.U32(value.Attributes);writer.U32(unchecked((uint)value.Creation.dwHighDateTime));writer.U32(unchecked((uint)value.Creation.dwLowDateTime));writer.Fixed(Wire.HashBytes(node.Security),32);}
                Information file=nodes[nodes.Count-1].Initial;writer.U32(file.SizeHigh);writer.U32(file.SizeLow);writer.U32(unchecked((uint)file.Write.dwHighDateTime));writer.U32(unchecked((uint)file.Write.dwLowDateTime));return writer.Bytes();}
        }
        private int Read(byte[] bytes,int offset,int count) {
            Check();Task<int> task=stream.ReadAsync(bytes,offset,count);try {while(!task.Wait(100)) Check();int read=task.GetAwaiter().GetResult();Check();return read;}
            catch {CancelIoEx(stream.SafeFileHandle,IntPtr.Zero);try {if(!task.Wait(2000)) stream.Dispose();}catch(AggregateException) {}throw;}
        }
        private byte[] Capture() {
            Check();stream.Position=0;byte[] bytes=new byte[intent.Bytes];try {int offset=0;while(offset<bytes.Length) {int count=Read(bytes,offset,Math.Min(32768,bytes.Length-offset));if(count==0) throw new EndOfStreamException("Exact enrolled source truncated.");offset+=count;}if(stream.Length!=bytes.Length) throw new SecurityException("Exact enrolled source grew.");using(SHA256 hash=SHA256.Create()) if(Wire.Hex(hash.ComputeHash(bytes))!=intent.Sha256) throw new SecurityException("Actual enrolled bytes differ from their reviewed complete source hash.");Check();return bytes;}catch {Array.Clear(bytes,0,bytes.Length);throw;}
        }
        internal byte[] CaptureVerified() {byte[] first=Capture();try {byte[] second=Capture();try {if(!Wire.Equal(first,second)) throw new SecurityException("Enrolled source changed across complete bounded observations.");}finally {Array.Clear(second,0,second.Length);}return first;}catch {Array.Clear(first,0,first.Length);throw;}}
        public void Dispose() {try {if(stream!=null) {stream.Dispose();stream=null;}}finally {try {foreach(Node node in nodes) node.Handle.Dispose();nodes.Clear();}finally {if(access!=null) {access.Dispose();access=null;}}}}
    }

    internal sealed class HostedReadInputs : IDisposable
    {
        internal readonly EnrolledReadIntent Intent;private byte[] content;private string source,review;private int received;private bool completed;private int cancelled;private readonly ConsoleCancelEventHandler cancel;
        internal HostedReadInputs(string[] arguments,bool interactive) {
            if(arguments.Length!=6) throw new InvalidDataException("Exact read arguments: INSTALLATION ROOT RELATIVE_PATH EXACT_BYTES SHA256.");int count;
            if(!Int32.TryParse(arguments[4],NumberStyles.None,CultureInfo.InvariantCulture,out count) || count.ToString(CultureInfo.InvariantCulture)!=arguments[4]) throw new SecurityException("Read byte count must be canonical positive decimal.");
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {if(identity.User==null) throw new SecurityException("Read intent has no observed Windows SID.");Intent=new EnrolledReadIntent(arguments[1],identity.User.Value,arguments[2],arguments[3],count,arguments[5]);}
            if(interactive) {cancel=delegate(object sender,ConsoleCancelEventArgs args) {Interlocked.Exchange(ref cancelled,1);args.Cancel=true;};Console.CancelKeyPress+=cancel;}
        }
        internal void Check() {if(Interlocked.CompareExchange(ref cancelled,0,0)!=0) throw new OperationCanceledException("Read cancelled. A partial byte transfer is possible; no complete receipt, publication or write is claimed.");}
        internal void Reviewed(byte[] exact,string reviewHash) {
            if(review!=null) throw new SecurityException("Read cannot replace its one exact review.");using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-read-review-v1")) {
                if(!Wire.Equal(reader.Blob(2048),Intent.Encode())) throw new SecurityException("Service substituted original selected read input.");byte[] snapshot=reader.Blob(4096);reader.End();
                Intent.ValidateSnapshot(snapshot);
                source=Wire.Hash(snapshot);review=reviewHash;Wire.Bytes(review,32,true);content=new byte[Intent.Bytes];
            }
        }
        internal byte[] Part(byte[] bytes) {
            Check();if(review==null || content==null || completed) throw new SecurityException("Source bytes arrived before original exact review or after completion.");using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-read-chunk-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=source || reader.U32()!=received) throw new SecurityException("Read chunk changed exact review, object or offset.");byte[] part=reader.Blob(32768);reader.End();
                try {if(part.Length!=Math.Min(32768,content.Length-received) || part.Length==0) throw new SecurityException("Read chunk changed exact byte budget.");Buffer.BlockCopy(part,0,content,received,part.Length);received+=part.Length;}finally {Array.Clear(part,0,part.Length);}
            }
            byte[] prefix;using(SHA256 hash=SHA256.Create()) prefix=hash.ComputeHash(content,0,received);using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-ack-v1")) {writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(source,32,true),32);writer.U32((uint)received);writer.Fixed(prefix,32);return writer.Bytes();}
        }
        internal void Completed(byte[] bytes) {
            Check();if(completed || review==null || content==null || received!=Intent.Bytes) throw new SecurityException("Partial, unreviewed or replayed read has no complete receipt.");using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-read-completed-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(Intent.Encode()) || Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=source || reader.U32()!=received || Wire.Hex(reader.Fixed(32))!=Intent.Sha256 || reader.U8()!=1) throw new SecurityException("Read completion changed original exact source or bytes.");
                for(int index=0;index<6;index++) if(reader.U8()!=0) throw new SecurityException("Read completion claims unsupported persistent enrollment, publication, Linux grants, writes or qualification.");reader.End();
            }
            using(SHA256 hash=SHA256.Create()) if(Wire.Hex(hash.ComputeHash(content))!=Intent.Sha256) throw new SecurityException("Client full source hash differs from actual received bytes.");completed=true;
        }
        internal string Summary() {return SummaryText(false);}
        internal string SummaryForPersistent() {return SummaryText(true);}
        private string SummaryText(bool persistent) {if(!completed) throw new SecurityException("Read did not complete.");return "Received "+received+" exact inert bytes in original-client ephemeral memory; SHA256 "+Intent.Sha256+(persistent?". The existing persistent enrollment was selected, not created or changed; no source file saved, content publication, Linux authority, write or production qualification.":". No file saved, persistent enrollment, content publication, Linux authority, write or production qualification.");}
        public void Dispose() {if(cancel!=null) Console.CancelKeyPress-=cancel;if(content!=null) {Array.Clear(content,0,content.Length);content=null;}}
        internal static int Describe(string[] arguments) {
            using(HostedReadInputs input=new HostedReadInputs(arguments,false)) {Console.WriteLine("Purpose: host-file-read (read-exact-file)\nActual input SID (not authority): "+input.Intent.Owner+"\nIntent SHA256 for separate native U-source review: "+Wire.Hash(input.Intent.Encode())+"\nIntent bytes (hex): "+Wire.Hex(input.Intent.Encode())+"\nNo source accessed, session admitted, persistent enrollment or product/Linux authority.");return 0;}
        }
    }

    internal static partial class HostedCoordinator
    {
        private static LiveUtcWindow ReadTime(PipeStream pipe,NativeAuthority authority,EnrolledReadIntent intent,Action original) {
            return SourceTime(pipe,authority,intent.Installation,Wire.Hash(intent.Encode()),1,4102444800000UL,original);
        }
        private static LiveUtcWindow SourceTime(PipeStream pipe,NativeAuthority authority,string installation,string source,ulong start,ulong end,Action original) {
            if(authority.Trust.TimeRevoked || authority.Trust.Pending!=null) throw new SecurityException("Read requires current non-revoked independent UTC, never a prepared handoff or local time.");
            LiveUtcWindow live=new LiveUtcWindow(authority.Trust.CurrentIdentity,source,start,end);byte[] challenge;
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-utc-challenge-v1")) {writer.Fixed(Wire.Bytes(installation,32,true),32);writer.Fixed(Wire.Bytes(live.Nonce,32,true),32);writer.Fixed(Wire.Bytes(source,32,true),32);challenge=writer.Bytes();}
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-time-relay-v1")) {writer.Text(authority.Trust.Endpoint,2048);writer.Blob(challenge,1024);Reply(pipe,"utc-challenge",writer.Bytes(),original);}
            byte[] delivery=HostedPipe.Read(pipe,original,Standard);try {using(Wire.Reader reader=new Wire.Reader(delivery,"luma-windows-hosted-utc-delivery-v1")) {live.Accept(reader.Blob(8192),reader.Fixed(64));reader.End();}}finally {Array.Clear(delivery,0,delivery.Length);}original();return live;
        }
        private static void ReadEnrolledFile(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running) {
            EnrolledReadIntent intent=EnrolledReadIntent.Decode(request.Blob(2048));request.End();Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);
                intent.Match(authority.Identity,actor.Sid);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());LiveUtcWindow utc=ReadTime(pipe,authority,intent,original);
                Action check=delegate {original();authority.State.Check();NoUncertainFileAuthority(authority);utc.Check();if(authority.Nv.ReadHead()!=history.Head) throw new SecurityException("Actual read authority changed during its finite original session.");original();};
                using(EnrolledReadSource source=new EnrolledReadSource(intent,actor.Token,check)) {
                    byte[] snapshot=source.Snapshot(),review;using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-read-review-v1")) {exact.Blob(intent.Encode(),2048);exact.Blob(snapshot,4096);
                        review=Review(pipe,"read-enrolled-file",exact.Bytes(),"Single-use first-Admin-owned READ only; 30-second original-client purpose.\nSource: "+intent.Path+"\nActual owner: "+actor.Sid+"\nExact bytes: "+intent.Bytes+"\nExpected SHA256: "+intent.Sha256+"\nHeld object/ancestor/ACL fingerprint: "+Wire.Hash(snapshot)+"\nNo folder enumeration, write, persistent enrollment, product content publication, ordinary-user mapping, Linux grant or automatic background ingestion. Source read requests no-recall but cloud-provider/no-hydration qualification and synchronous kernel hard deadlines are not claimed. Cancellation/refusal may leave partial bytes delivered to this same original client.",check);}
                    EnrolledReadDelivery delivery=new EnrolledReadDelivery(intent,Wire.Hash(review),Wire.Hash(snapshot));source.Check();delivery.Begin(Wire.Hash(intent.Encode()),Wire.Hash(source.Snapshot()));byte[] content=source.CaptureVerified();
                    try {
                        while(delivery.Delivered<content.Length) {source.Check();byte[] chunk=delivery.Chunk(content,(int)delivery.Delivered);try {Reply(pipe,"read-chunk",chunk,source.Check);}finally {Array.Clear(chunk,0,chunk.Length);}byte[] ack=HostedPipe.Read(pipe,source.Check,Standard);try {source.Check();delivery.Acknowledge(ack,content);}finally {Array.Clear(ack,0,ack.Length);}}
                        byte[] after=source.CaptureVerified();try {if(!Wire.Equal(content,after)) throw new SecurityException("Source changed after byte delivery; no complete receipt is issued.");}finally {Array.Clear(after,0,after.Length);}
                        source.Check();Reply(pipe,"read-completed",delivery.Complete(),source.Check);
                    }finally {Array.Clear(content,0,content.Length);}
                }
            }
        }
    }
}
