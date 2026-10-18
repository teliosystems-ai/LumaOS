using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    public sealed class RuntimeComponent
    {
        public string Name {get;private set;}public long Bytes {get;private set;}public string Sha256 {get;private set;}
        public RuntimeComponent(string name,long bytes,string sha) {if(name==null || bytes<64 || bytes>134217728) throw new InvalidDataException("Runtime component length differs.");Wire.Bytes(sha,32,true);Name=name;Bytes=bytes;Sha256=sha;}
    }
    public sealed class RuntimeBundle
    {
        private static readonly string[] Names={"Luma.HostedAuthority.exe","Luma.PackageInspector.dll","Luma.PlatformCustody.dll","Luma.PlatformSignature.dll"};
        private readonly RuntimeComponent[] components;public RuntimeComponent[] Components {get{return (RuntimeComponent[])components.Clone();}}
        public string ServiceSha256 {get{return components[0].Sha256;}}public string Sha256 {get;private set;}
        public RuntimeBundle(RuntimeComponent[] values) {
            if(values==null || values.Length!=4) throw new InvalidDataException("Exact four-component runtime bundle required.");components=new RuntimeComponent[4];StringBuilder table=new StringBuilder("luma-windows-hosted-runtime-bundle-v1\n");
            for(int index=0;index<4;index++) {RuntimeComponent value=values[index];if(value==null || value.Name!=Names[index]) throw new SecurityException("Runtime bundle names/order differ from the closed installer layout.");
                components[index]=new RuntimeComponent(value.Name,value.Bytes,value.Sha256);table.Append(value.Name).Append('\t').Append(value.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\t').Append(value.Sha256).Append('\n');}
            Sha256=Wire.Hash(Encoding.UTF8.GetBytes(table.ToString()));
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-bundle-fields-v1")) {foreach(RuntimeComponent component in components) {writer.Text(component.Name,64);writer.U64((ulong)component.Bytes);writer.Fixed(Wire.Bytes(component.Sha256,32,true),32);}return writer.Bytes();}}
        public static RuntimeBundle Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-bundle-fields-v1")) {RuntimeComponent[] values=new RuntimeComponent[4];for(int index=0;index<4;index++) {string name=reader.Text(64);ulong count=reader.U64();if(count>134217728) throw new SecurityException("Runtime component length exceeds fixed bound.");values[index]=new RuntimeComponent(name,(long)count,Wire.Hex(reader.Fixed(32)));}reader.End();return new RuntimeBundle(values);}}
    }
    public sealed class RuntimeUpdate
    {
        public string Installation {get;private set;}public ulong Generation {get;private set;}public string Previous {get;private set;}
        public ulong NotBefore {get;private set;}public ulong Expires {get;private set;}public RuntimeBundle Bundle {get;private set;}public string WslSha256 {get;private set;}
        public RuntimeUpdate(string installation,ulong generation,string previous,ulong notBefore,ulong expires,RuntimeBundle bundle,string wsl) {
            Wire.Bytes(installation,32,true);Wire.Bytes(previous,32,true);Wire.Bytes(wsl,32,true);
            if(generation<1 || generation>1024 || notBefore==0 || expires<=notBefore || expires>4102444800000UL || expires-notBefore>604800000UL || bundle==null) throw new InvalidDataException("Runtime update generation/lifetime/bundle differs.");
            Installation=installation;Generation=generation;Previous=previous;NotBefore=notBefore;Expires=expires;Bundle=bundle;WslSha256=wsl;
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-update-v1")) {writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.U64(Generation);writer.Fixed(Wire.Bytes(Previous,32,true),32);writer.U64(NotBefore);writer.U64(Expires);writer.Blob(Bundle.Encode(),1024);writer.Fixed(Wire.Bytes(WslSha256,32,true),32);return writer.Bytes();}}
        public static RuntimeUpdate Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-update-v1")) {RuntimeUpdate result=new RuntimeUpdate(Wire.Hex(reader.Fixed(32)),reader.U64(),Wire.Hex(reader.Fixed(32)),reader.U64(),reader.U64(),RuntimeBundle.Decode(reader.Blob(1024)),Wire.Hex(reader.Fixed(32)));reader.End();return result;}}
        public byte[] SigningInput() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-publisher-v1")) {writer.Fixed(Wire.HashBytes(Encode()),32);return writer.Bytes();}}
        public void Verify(AuthorityIdentity identity,byte[] signature) {if(identity.Domain!="host-deployment" || Installation!=identity.Installation || !Luma.Windows.PlatformSignature.Verify(identity.ReleaseKey,SigningInput(),Wire.Copy(signature,64,64))) throw new SecurityException("Runtime update lacks the exact current publisher signature/installation.");}
    }
    public sealed class RuntimePreparation
    {
        public RuntimeUpdate Update {get;private set;}public string Slot {get;private set;}private readonly byte[] signature,proof,timeSignature;
        public RuntimePreparation(RuntimeUpdate update,string slot,byte[] signature,byte[] proof,byte[] timeSignature) {if(update==null) throw new ArgumentNullException("update");Wire.Bytes(slot,32,true);Update=update;Slot=slot;this.signature=Wire.Copy(signature,64,64);this.proof=Wire.Copy(proof,1,512);this.timeSignature=Wire.Copy(timeSignature,64,64);}
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-prepared-v1")) {writer.Blob(Update.Encode(),2048);writer.Fixed(Wire.Bytes(Slot,32,true),32);writer.Fixed(signature,64);writer.Blob(proof,512);writer.Fixed(timeSignature,64);return writer.Bytes();}}
        public static RuntimePreparation Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-prepared-v1")) {RuntimePreparation result=new RuntimePreparation(RuntimeUpdate.Decode(reader.Blob(2048)),Wire.Hex(reader.Fixed(32)),reader.Fixed(64),reader.Blob(512),reader.Fixed(64));reader.End();return result;}}
        internal void Validate(AuthorityIdentity identity) {Update.Verify(identity,signature);LiveUtcWindow.Validate(identity,Wire.Hash(Update.Encode()),Update.NotBefore,Update.Expires,TimeAttestation.Decode(proof),timeSignature);}
    }
    public sealed class RuntimeCompletion
    {
        public string PreparedSha256 {get;private set;}public bool Cancelled {get;private set;}private readonly byte[] publisher,proof,timeSignature;
        public RuntimeCompletion(string prepared,bool cancelled,byte[] publisher,byte[] proof,byte[] timeSignature) {Wire.Bytes(prepared,32,true);PreparedSha256=prepared;Cancelled=cancelled;this.publisher=Wire.Copy(publisher,64,64);this.proof=Wire.Copy(proof,1,512);this.timeSignature=Wire.Copy(timeSignature,64,64);}
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-completed-v1")) {writer.Fixed(Wire.Bytes(PreparedSha256,32,true),32);writer.U8(Cancelled?(byte)1:(byte)0);writer.Fixed(publisher,64);writer.Blob(proof,512);writer.Fixed(timeSignature,64);return writer.Bytes();}}
        public static RuntimeCompletion Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-completed-v1")) {string prepared=Wire.Hex(reader.Fixed(32));byte mode=reader.U8();if(mode>1) throw new SecurityException("Runtime completion mode differs.");RuntimeCompletion result=new RuntimeCompletion(prepared,mode==1,reader.Fixed(64),reader.Blob(512),reader.Fixed(64));reader.End();return result;}}
        internal void Validate(RuntimePreparation pending,AuthorityIdentity current,bool effectsAllowed) {
            if(pending==null || PreparedSha256!=Wire.Hash(pending.Encode())) throw new SecurityException("Runtime completion has no exact committed preparation.");
            if(!Cancelled) {if(!effectsAllowed) throw new SecurityException("Runtime activation crossed revoked/prepared trust.");pending.Update.Verify(current,publisher);}
            else if(Wire.Hex(publisher)!=new string('0',128)) throw new SecurityException("Runtime cancellation does not treat a publisher signature as cleanup authority.");
            LiveUtcWindow.Validate(current,Wire.Hash(pending.Update.Encode()),Cancelled?1:pending.Update.NotBefore,Cancelled?4102444800000UL:pending.Update.Expires,TimeAttestation.Decode(proof),timeSignature);
        }
    }
    public sealed class RecordedTrust
    {
        public AuthorityIdentity Identity {get;private set;}public bool EffectsAllowed {get;private set;}public bool TimeAllowed {get;private set;}
        internal RecordedTrust(AuthorityIdentity identity,bool effects,bool time) {Identity=identity;EffectsAllowed=effects;TimeAllowed=time;}
    }
    public sealed class HostedRuntimeState
    {
        public RuntimeBundle Current {get;private set;}public string WslSha256 {get;private set;}public string Slot {get;private set;}
        public string SourceSha256 {get;private set;}public ulong Generation {get;private set;}public RuntimePreparation Pending {get;private set;}
        private readonly HashSet<string> slots=new HashSet<string>(StringComparer.Ordinal);
        private HostedRuntimeState(AuthorityIdentity identity,RuntimeBundle baseline) {if(baseline==null || baseline.ServiceSha256!=identity.ServiceSha256) throw new SecurityException("Commissioned full runtime baseline is missing or mismatched.");Current=baseline;WslSha256=identity.WslSha256;Slot="";
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-genesis-v1")) {writer.Fixed(Wire.HashBytes(identity.Encode()),32);writer.Fixed(Wire.Bytes(baseline.Sha256,32,true),32);SourceSha256=Wire.Hash(writer.Bytes());}}
        public static HostedRuntimeState Replay(AuthorityIdentity identity,RuntimeBundle baseline,HostedTrustState trust,JournalHistory history,Action check) {
            if(check==null || trust==null || history==null) throw new ArgumentNullException("check");check();HostedRuntimeState state=new HostedRuntimeState(identity,baseline);
            foreach(JournalEntry entry in history.Entries) {
                check();if(entry.Kind==JournalKind.RuntimePrepared) {
                    RuntimePreparation pending=RuntimePreparation.Decode(entry.Payload);RecordedTrust at=trust.At(entry.Sequence);
                    if(state.Pending!=null || !at.EffectsAllowed || pending.Update.Generation!=checked(state.Generation+1) || pending.Update.Previous!=state.SourceSha256 || !state.slots.Add(pending.Slot) ||
                        pending.Update.Bundle.Sha256==state.Current.Sha256 && pending.Update.WslSha256==state.WslSha256) throw new SecurityException("Runtime admission is concurrent, replayed, stale or unchanged.");
                    pending.Validate(at.Identity);state.Pending=pending;
                } else if(entry.Kind==JournalKind.RuntimeActivated || entry.Kind==JournalKind.RuntimeCancelled) {
                    RuntimeCompletion completed=RuntimeCompletion.Decode(entry.Payload);RecordedTrust at=trust.At(entry.Sequence);
                    if(state.Pending==null || !at.TimeAllowed || (entry.Kind==JournalKind.RuntimeCancelled)!=completed.Cancelled) throw new SecurityException("Runtime completion mode or current independent time differs.");
                    completed.Validate(state.Pending,at.Identity,at.EffectsAllowed);state.Generation=state.Pending.Update.Generation;state.SourceSha256=Wire.Hash(completed.Encode());
                    if(!completed.Cancelled) {state.Current=state.Pending.Update.Bundle;state.WslSha256=state.Pending.Update.WslSha256;state.Slot=state.Pending.Slot;}state.Pending=null;
                }
            }
            check();return state;
        }
    }

    internal enum RuntimeAccess { Standard,Inspect,Prepare,Continue }
    public static class RuntimePermissionPolicy
    {
        public static void Validate(byte[] bytes,bool directory,bool staged,string service) {
            if(staged) Wire.Sid(service);RawSecurityDescriptor value=new RawSecurityDescriptor(Wire.Copy(bytes,20,65536),0);
            string owner=staged?"S-1-5-18":"S-1-5-32-544";
            if(value.Owner==null || value.Owner.Value!=owner || (value.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || value.DiscretionaryAcl==null || value.DiscretionaryAcl.Count!=(staged?4:3)) throw new SecurityException("Installed runtime owner or protected exact ACL differs.");
            Dictionary<string,int> expected=new Dictionary<string,int>(StringComparer.Ordinal) {{"S-1-5-18",0x1f01ff},{"S-1-5-32-544",0x1f01ff},{"S-1-5-32-545",0x1200a9}};if(staged) expected.Add(service,0x1f01ff);
            foreach(GenericAce item in value.DiscretionaryAcl) {CommonAce ace=item as CommonAce;int mask;
                if(ace==null || ace.IsCallback || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=(directory?AceFlags.ObjectInherit|AceFlags.ContainerInherit:AceFlags.None) ||
                    !expected.TryGetValue(ace.SecurityIdentifier.Value,out mask) || ace.AccessMask!=mask) throw new SecurityException("Installed runtime contains writable/unreviewed principals or inheritance.");expected.Remove(ace.SecurityIdentifier.Value);
            }
            if(expected.Count!=0) throw new SecurityException("Installed runtime omits fixed principals.");
        }
    }
    internal sealed class InstalledRuntimeLease : IDisposable
    {
        private readonly List<InstalledInputLease> leases=new List<InstalledInputLease>();private readonly Action original;private readonly string slot;
        internal InstalledRuntimeLease(string slot,RuntimeBundle expected,Action original) {
            this.original=original;this.slot=slot;
            try {foreach(RuntimeComponent component in expected.Components) {
                original();string path=Path.Combine(HostedRuntimeFiles.DirectoryFor(slot),component.Name);InstalledInputLease lease=InstalledInputLease.Acquire(path);leases.Add(lease);Stream file=lease.Rewind();
                if(lease.Length!=component.Bytes) throw new SecurityException("Held installed runtime component length differs.");using(SHA256 hash=SHA256.Create()) {byte[] block=new byte[32768];while(true) {Check();int count=file.Read(block,0,block.Length);if(count==0) break;hash.TransformBlock(block,0,count,null,0);}hash.TransformFinalBlock(new byte[0],0,0);if(Wire.Hex(hash.Hash)!=component.Sha256) throw new SecurityException("Held installed runtime component digest differs.");}
            }Check();} catch {Dispose();throw;}
        }
        internal void Check() {original();HostedRuntimeFiles.RequireLayout(slot);HostedRuntimeFiles.RequirePermissions(slot);foreach(InstalledInputLease lease in leases) lease.Check();}
        public void Dispose() {foreach(InstalledInputLease lease in leases) lease.Dispose();leases.Clear();}
    }
    internal static class HostedRuntimeFiles
    {
        [StructLayout(LayoutKind.Sequential)] private struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information information);
        private static void CheckDirectory(SafeFileHandle handle) {Information value;if(handle.IsInvalid || !GetFileInformationByHandle(handle,out value)) throw new Win32Exception(Marshal.GetLastWin32Error());if((value.Attributes&0x10)==0 || (value.Attributes&(0x400|0x1000|0x40000|0x400000))!=0) throw new SecurityException("Runtime directory is linked, cloud-backed, recalled or not a directory.");}
        private static SafeFileHandle PinDirectory(string path) {SafeFileHandle result=CreateFile(path,0x20081,3,IntPtr.Zero,3,0x02300000,IntPtr.Zero);try {CheckDirectory(result);return result;}catch {result.Dispose();throw;}}
        internal static string Root {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"LumaOS-HostedAuthority");}}
        internal static string DirectoryFor(string slot) {if(slot=="") return Root;Wire.Bytes(slot,32,true);return Path.Combine(Root,"releases",slot);}
        internal static string Executable(string slot) {return Path.Combine(DirectoryFor(slot),"Luma.HostedAuthority.exe");}
        internal static string Running {get{return Process.GetCurrentProcess().MainModule.FileName;}}
        internal static void RequireLayout(string slot) {
            string directory=DirectoryFor(slot);HashSet<string> names=new HashSet<string>(new string[]{"Luma.HostedAuthority.exe","Luma.PackageInspector.dll","Luma.PlatformCustody.dll","Luma.PlatformSignature.dll"},StringComparer.Ordinal);
            foreach(string file in Directory.EnumerateFiles(directory,"*",SearchOption.TopDirectoryOnly)) if(!names.Remove(Path.GetFileName(file))) throw new SecurityException("Installed runtime contains an unreviewed file, CLR config or code-loading sidecar.");
            if(names.Count!=0) throw new SecurityException("Installed runtime omits an exact required EXE/DLL component.");
            bool releases=false;foreach(string path in Directory.EnumerateDirectories(directory,"*",SearchOption.TopDirectoryOnly)) {if(slot!="" || releases || Path.GetFileName(path)!="releases") throw new SecurityException("Installed runtime contains an unreviewed directory.");using(SafeFileHandle pin=PinDirectory(path)) CheckDirectory(pin);releases=true;}
        }
        private static void RequireFilePermissions(string path,bool staged,string service) {RuntimePermissionPolicy.Validate(File.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),false,staged,service);}
        internal static void RequirePermissions(string slot) {
            string service=FixedServiceIdentity.Require().Value;RuntimePermissionPolicy.Validate(Directory.GetAccessControl(Root,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),true,false,service);
            if(slot!="") {
                string parent=Path.Combine(Root,"releases"),directory=DirectoryFor(slot);RuntimePermissionPolicy.Validate(Directory.GetAccessControl(parent,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),true,true,service);RuntimePermissionPolicy.Validate(Directory.GetAccessControl(directory,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),true,true,service);
            }
            foreach(string name in new string[]{"Luma.HostedAuthority.exe","Luma.PackageInspector.dll","Luma.PlatformCustody.dll","Luma.PlatformSignature.dll"}) RequireFilePermissions(Path.Combine(DirectoryFor(slot),name),slot!="",service);
        }
        internal static void RequireLoadedOrigins(string slot) {
            string directory=DirectoryFor(slot);string[] observed={typeof(HostedCoordinator).Assembly.Location,typeof(Luma.Windows.PackageInspector).Assembly.Location,typeof(Luma.Windows.PlatformCustodyProtocol).Assembly.Location,typeof(Luma.Windows.PlatformSignature).Assembly.Location};
            string[] names={"Luma.HostedAuthority.exe","Luma.PackageInspector.dll","Luma.PlatformCustody.dll","Luma.PlatformSignature.dll"};
            for(int index=0;index<4;index++) if(!String.Equals(observed[index],Path.Combine(directory,names[index]),StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Actual loaded EXE/DLL origin is outside the exact installed runtime slot.");
        }
        internal static RuntimeBundle Capture(string slot,Action check) {
            check();RequireLayout(slot);RequirePermissions(slot);string path=DirectoryFor(slot);RuntimeComponent[] observed=new RuntimeComponent[4];string[] names={"Luma.HostedAuthority.exe","Luma.PackageInspector.dll","Luma.PlatformCustody.dll","Luma.PlatformSignature.dll"};
            for(int index=0;index<4;index++) {check();string file=Path.Combine(path,names[index]);using(InstalledInputLease lease=InstalledInputLease.Acquire(file)) {Stream input=lease.Rewind();
                if(lease.Length<64 || lease.Length>134217728) throw new SecurityException("Actual runtime component exceeds its fixed bound.");using(SHA256 hash=SHA256.Create()) {byte[] block=new byte[32768];while(true) {check();lease.Check();int count=input.Read(block,0,block.Length);if(count==0) break;hash.TransformBlock(block,0,count,null,0);}hash.TransformFinalBlock(new byte[0],0,0);lease.Check();observed[index]=new RuntimeComponent(names[index],lease.Length,Wire.Hex(hash.Hash));}
            }}return new RuntimeBundle(observed);
        }
        internal static void Require(string slot,RuntimeBundle bundle,Action check) {if(Capture(slot,check).Sha256!=bundle.Sha256) throw new SecurityException("Actual full EXE/DLL runtime bundle differs from its immutable reviewed pins.");}
        internal static void CheckRunning(HostedRuntimeState state,RuntimeAccess access,Action check) {
            check();bool old=String.Equals(Running,Executable(state.Slot),StringComparison.OrdinalIgnoreCase),next=state.Pending!=null && String.Equals(Running,Executable(state.Pending.Slot),StringComparison.OrdinalIgnoreCase);
            if(!old && !next) throw new SecurityException("Actual service path is neither the exact current nor prepared runtime slot.");
            RequireLoadedOrigins(old?state.Slot:state.Pending.Slot);
            if(old) Require(state.Slot,state.Current,check);else Require(state.Pending.Slot,state.Pending.Update.Bundle,check);
            if(access==RuntimeAccess.Standard && (state.Pending!=null || !old)) throw new SecurityException("Runtime migration is pending; effects require explicit post-restart finalize.");
            string actual=HostedCoordinator.FileHash(Path.Combine(Environment.SystemDirectory,"wsl.exe"));
            if(access==RuntimeAccess.Standard && actual!=state.WslSha256 || access==RuntimeAccess.Continue && actual!=state.WslSha256 && (state.Pending==null || actual!=state.Pending.Update.WslSha256)) throw new SecurityException("Actual fixed WSL dependency is outside the exact allowed runtime transition.");check();
        }
        private static void DirectorySecurity(string path,string descriptor) {
            DirectorySecurity security=new DirectorySecurity();security.SetSecurityDescriptorSddlForm(descriptor,AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.CreateDirectory(path,security);
            using(SafeFileHandle pin=PinDirectory(path)) {
            RawSecurityDescriptor actual=new RawSecurityDescriptor(Directory.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),0),expected=new RawSecurityDescriptor(descriptor);
            if(actual.Owner==null || actual.Owner.Value!="S-1-5-18" || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || actual.DiscretionaryAcl==null || actual.DiscretionaryAcl.Count!=expected.DiscretionaryAcl.Count) throw new SecurityException("Staged runtime directory owner/protected ACL differs.");
            Dictionary<string,int> required=new Dictionary<string,int>(StringComparer.Ordinal);foreach(GenericAce item in expected.DiscretionaryAcl) {CommonAce ace=(CommonAce)item;required.Add(ace.SecurityIdentifier.Value,ace.AccessMask);}
            foreach(GenericAce item in actual.DiscretionaryAcl) {CommonAce ace=item as CommonAce;int rights;if(ace==null || ace.IsCallback || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=(AceFlags.ObjectInherit|AceFlags.ContainerInherit) || !required.TryGetValue(ace.SecurityIdentifier.Value,out rights) || rights!=ace.AccessMask) throw new SecurityException("Staged runtime contains extra/inherited ACL authority.");required.Remove(ace.SecurityIdentifier.Value);}if(required.Count!=0) throw new SecurityException("Staged runtime omitted fixed principals.");
            CheckDirectory(pin);}
        }
        internal static void Stage(RuntimePreparation preparation,Func<int,long,byte[]> next,Action check) {
            check();string service=FixedServiceIdentity.Require().Value,root=Root;using(InstalledInputLease parent=InstalledInputLease.Acquire(Path.Combine(root,"Luma.HostedAuthority.exe"))) {
                if(new DriveInfo(Path.GetPathRoot(root)).DriveFormat!="NTFS") throw new SecurityException("Installed runtime migration requires native NTFS.");
                string descriptor="O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+service+")(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
                string releases=Path.Combine(root,"releases"),slot=DirectoryFor(preparation.Slot);DirectorySecurity(releases,descriptor);
                using(SafeFileHandle releasePin=PinDirectory(releases)) {
                if(Directory.Exists(slot) || File.Exists(slot)) throw new SecurityException("A runtime generation slot is never overwritten or adopted.");DirectorySecurity(slot,descriptor);
                using(SafeFileHandle slotPin=PinDirectory(slot)) {
                long needed=1073741824;foreach(RuntimeComponent component in preparation.Update.Bundle.Components) needed=checked(needed+component.Bytes);if(new DriveInfo(Path.GetPathRoot(slot)).AvailableFreeSpace<needed) throw new IOException("Actual NTFS runtime staging capacity is insufficient.");
                RuntimeComponent[] components=preparation.Update.Bundle.Components;
                for(int index=0;index<components.Length;index++) {RuntimeComponent component=components[index];check();parent.Check();DirectorySecurity(releases,descriptor);DirectorySecurity(slot,descriptor);
                    using(FileStream output=new FileStream(Path.Combine(slot,component.Name),FileMode.CreateNew,FileAccess.Write,FileShare.None,32768,FileOptions.WriteThrough)) using(SHA256 hash=SHA256.Create()) {
                        long at=0;while(at<component.Bytes) {check();parent.Check();CheckDirectory(releasePin);CheckDirectory(slotPin);DirectorySecurity(releases,descriptor);DirectorySecurity(slot,descriptor);byte[] bytes=next(index,at);if(bytes==null || bytes.Length!=Math.Min(32768,component.Bytes-at)) throw new SecurityException("Exact original-client runtime source chunk differs.");check();output.Write(bytes,0,bytes.Length);hash.TransformBlock(bytes,0,bytes.Length,null,0);at+=bytes.Length;}
                        hash.TransformFinalBlock(new byte[0],0,0);if(Wire.Hex(hash.Hash)!=component.Sha256 || output.Length!=component.Bytes) throw new SecurityException("Complete runtime component differs from the signed bundle.");check();output.Flush(true);
                    }
                    FileSecurity security=new FileSecurity();security.SetSecurityDescriptorSddlForm("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;"+service+")(A;;FA;;;BA)(A;;0x1200a9;;;BU)",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);File.SetAccessControl(Path.Combine(slot,component.Name),security);RequireFilePermissions(Path.Combine(slot,component.Name),true,service);
                }
                Require(preparation.Slot,preparation.Update.Bundle,check);parent.Check();
                }}
            }
        }
    }

    internal static class HostedRuntimeScm
    {
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Configuration {public uint Type,Start,Error;public IntPtr Binary,Group;public uint Tag;public IntPtr Dependencies,Account,Display;}
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool QueryServiceConfig(IntPtr service,IntPtr buffer,uint bytes,out uint needed);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool ChangeServiceConfig(IntPtr service,uint type,uint start,uint error,string image,string group,IntPtr tag,string dependencies,string account,string password,string display);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        internal static string Image(string slot) {return "\""+HostedRuntimeFiles.Executable(slot)+"\" service";}
        private static string Text(IntPtr buffer,uint bytes,IntPtr pointer,int maximum) {
            long offset=pointer.ToInt64()-buffer.ToInt64();if(offset<0 || offset>=bytes || (offset&1)!=0) throw new SecurityException("SCM returned an out-of-buffer text pointer.");
            for(int count=0;count<=maximum;count++) {if(offset+(long)count*2+2>bytes) throw new SecurityException("SCM text has no bounded terminator.");if(Marshal.ReadInt16(pointer,count*2)==0) return Marshal.PtrToStringUni(pointer,count);}throw new SecurityException("SCM text exceeds its exact bound.");
        }
        private static string Read(IntPtr service) {
            uint needed;QueryServiceConfig(service,IntPtr.Zero,0,out needed);if(needed<Marshal.SizeOf(typeof(Configuration)) || needed>8192) throw new SecurityException("Actual SCM configuration exceeds bound.");IntPtr buffer=Marshal.AllocHGlobal((int)needed);
            try {uint actual;if(!QueryServiceConfig(service,buffer,needed,out actual)) throw new Win32Exception(Marshal.GetLastWin32Error());Configuration value=(Configuration)Marshal.PtrToStructure(buffer,typeof(Configuration));
                long offset=value.Binary.ToInt64()-buffer.ToInt64(),account=value.Account.ToInt64()-buffer.ToInt64();if(value.Type!=16 || offset<0 || offset>=needed || account<0 || account>=needed) throw new SecurityException("Actual SCM own-process/pointer configuration differs.");
                string binary=Text(buffer,needed,value.Binary,1024),owner=Text(buffer,needed,value.Account,64);if(owner!="LocalSystem") throw new SecurityException("Actual SCM image/account differs.");return binary;
            } finally {Marshal.FreeHGlobal(buffer);}
        }
        internal static void Require(HostedRuntimeState state,bool proposed,Action check) {Operate(state,proposed,false,check);}
        internal static void Switch(HostedRuntimeState state,bool proposed,Action check) {Operate(state,proposed,true,check);}
        private static void Operate(HostedRuntimeState state,bool proposed,bool change,Action check) {
            check();FixedServiceIdentity.Require();if(state.Pending==null) throw new SecurityException("SCM transition requires an exact committed runtime generation.");IntPtr manager=IntPtr.Zero,service=IntPtr.Zero;
            try {manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());service=OpenService(manager,FixedServiceIdentity.Name,change?3U:1U);if(service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                string before=Read(service),old=Image(state.Slot),next=Image(state.Pending.Slot),target=proposed?next:old;if(before!=old && before!=next) throw new SecurityException("SCM points outside the exact current/prepared runtime slots.");
                if(change) {check();if(!ChangeServiceConfig(service,UInt32.MaxValue,UInt32.MaxValue,UInt32.MaxValue,target,null,IntPtr.Zero,null,null,null,null)) throw new Win32Exception(Marshal.GetLastWin32Error());}
                if(Read(service)!=target) throw new SecurityException("Actual configured SCM image is not the exact requested pinned generation.");check();
            } finally {if(service!=IntPtr.Zero) CloseServiceHandle(service);if(manager!=IntPtr.Zero) CloseServiceHandle(manager);}
        }
    }
}
