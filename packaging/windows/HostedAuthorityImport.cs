using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    internal sealed class HostedGuestDirectory : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Information {
            public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Access,Write;
            public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
        }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information information);
        private readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();private readonly List<Information> initial=new List<Information>();
        private readonly List<string> paths=new List<string>();private readonly List<string> descriptors=new List<string>();
        internal string Path {get;private set;}
        private HostedGuestDirectory() {}
        private void Pin(string path,string descriptor)
        {
            SafeFileHandle handle=CreateFile(path,0x20081,3,IntPtr.Zero,3,0x02300000,IntPtr.Zero);
            if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
            try {Information info=Inspect(handle);handles.Add(handle);initial.Add(info);paths.Add(path);descriptors.Add(descriptor);Check();}
            catch {if(!handles.Contains(handle)) handle.Dispose();throw;}
        }
        private static Information Inspect(SafeFileHandle handle)
        {
            Information value;if(!GetFileInformationByHandle(handle,out value)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if((value.Attributes&0x10)==0 || (value.Attributes&(0x400|0x1000|0x40000|0x400000))!=0) throw new SecurityException("Owned guest directory is linked, recalled, cloud-backed or not a directory.");return value;
        }
        private static void RequireSecurity(string path,string expected)
        {
            RawSecurityDescriptor actual=new RawSecurityDescriptor(Directory.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access).GetSecurityDescriptorBinaryForm(),0);
            RawSecurityDescriptor wanted=new RawSecurityDescriptor(expected);
            if(actual.Owner==null || actual.Owner.Value!="S-1-5-18" || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
                actual.DiscretionaryAcl==null || actual.DiscretionaryAcl.Count!=wanted.DiscretionaryAcl.Count) throw new SecurityException("Owned guest directory owner or protected ACL differs.");
            Dictionary<string,int> permissions=new Dictionary<string,int>(StringComparer.Ordinal);
            foreach(GenericAce item in wanted.DiscretionaryAcl) {CommonAce ace=(CommonAce)item;permissions.Add(ace.SecurityIdentifier.Value,ace.AccessMask);}
            foreach(GenericAce item in actual.DiscretionaryAcl) {
                CommonAce ace=item as CommonAce;int permission;
                if(ace==null || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.IsCallback || ace.AceFlags!=(AceFlags.ContainerInherit|AceFlags.ObjectInherit) ||
                    !permissions.TryGetValue(ace.SecurityIdentifier.Value,out permission) || permission!=ace.AccessMask) throw new SecurityException("Owned guest directory contains unreviewed or inherited ACL authority.");permissions.Remove(ace.SecurityIdentifier.Value);
            }
            if(permissions.Count!=0) throw new SecurityException("Owned guest directory omitted a fixed principal.");
        }
        internal void Check()
        {
            FixedServiceIdentity.Require();for(int index=0;index<handles.Count;index++) {
                Information now=Inspect(handles[index]),before=initial[index];if(now.Volume!=before.Volume || now.IndexHigh!=before.IndexHigh || now.IndexLow!=before.IndexLow || now.Attributes!=before.Attributes ||
                    now.Created.dwHighDateTime!=before.Created.dwHighDateTime || now.Created.dwLowDateTime!=before.Created.dwLowDateTime) throw new SecurityException("Pinned owned guest directory changed.");
                if(descriptors[index]!=null) RequireSecurity(paths[index],descriptors[index]);
            }
        }
        internal static HostedGuestDirectory Open(AuthorityIdentity identity,DeploymentEvent admission,bool fresh)
        {
            FixedServiceIdentity.Require();string name=HostedGuestRunner.Distribution(identity,admission);string common=System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData);
            HostedGuestDirectory result=new HostedGuestDirectory();
            try {
                string root=System.IO.Path.GetPathRoot(common);if(new DriveInfo(root).DriveFormat!="NTFS") throw new SecurityException("Live owned guest images require NTFS protected ACLs, not an exFAT build/archive volume.");
                string path=root;result.Pin(root,null);foreach(string part in common.Substring(root.Length).Split('\\')) {path=System.IO.Path.Combine(path,part);result.Pin(path,null);}
                string service=FixedServiceIdentity.Require().Value;
                string parent="O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+service+")(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+identity.FirstAdminSid+")";
                path=System.IO.Path.Combine(common,"LumaOS-HostedGuests");DirectorySecurity security=new DirectorySecurity();security.SetSecurityDescriptorSddlForm(parent);
                Directory.CreateDirectory(path,security);result.Pin(path,parent);
                string leaf="O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+service+")(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+identity.FirstAdminSid+")";
                path=System.IO.Path.Combine(path,name);if(fresh && (Directory.Exists(path)||File.Exists(path))) throw new SecurityException("Existing owned slot is not overwritten or adopted by a fresh import.");
                if(fresh) {security=new DirectorySecurity();security.SetSecurityDescriptorSddlForm(leaf);Directory.CreateDirectory(path,security);}
                result.Pin(path,leaf);result.Path=path;return result;
            } catch {result.Dispose();throw;}
        }
        public void Dispose() {for(int index=handles.Count-1;index>=0;index--) handles[index].Dispose();handles.Clear();initial.Clear();paths.Clear();descriptors.Clear();}
    }

    internal static class HostedImportProcess
    {
        internal static string Run(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,HostedGuestDirectory destination,StagedPackage package,Action<OwnedWindowsProcess> registered,Action live)
        {
            live();destination.Check();if(HostedWslConfiguration.Registered(identity,actor,admission)) throw new SecurityException("Fresh import refuses every existing registered slot.");
            string[] arguments={"--import",HostedGuestRunner.Distribution(identity,admission),destination.Path,"-","--version","2"};
            using(PinnedWsl binary=new PinnedWsl(identity.WslSha256)) using(OwnedWindowsProcess process=OwnedWindowsProcess.Start(binary,actor,arguments,registered)) {
                Stopwatch deadline=Stopwatch.StartNew();TimeSpan maximum=TimeSpan.FromMinutes(30);
                Task<byte[]> output=Task.Factory.StartNew(delegate {return DrainOutput(process.Output,65536);});Task<byte[]> errors=Task.Factory.StartNew(delegate {return DrainOutput(process.Error,4096);});
                Action check=delegate {live();destination.Check();binary.Check();if(output.IsFaulted) output.GetAwaiter().GetResult();if(errors.IsFaulted) errors.GetAwaiter().GetResult();};
                Stream source=package.Rewind();byte[] block=new byte[32768];while(true) {
                    check();int count=source.Read(block,0,block.Length);if(count==0) break;
                    GuestComputeFrames.Await(Task.Factory.StartNew(delegate {process.Input.Write(block,0,count);process.Input.Flush();return true;}),check,deadline,maximum);
                }
                process.Input.Close();process.RequireSuccess(check,maximum-deadline.Elapsed);
                byte[] observed=GuestComputeFrames.Await(output,check,deadline,maximum);GuestComputeFrames.Await(errors,check,deadline,maximum);
                if(!process.Exited) throw new SecurityException("Original import controller exit is unobserved.");check();
                return PackageInspector.Sha256(observed);
            }
        }
        private static byte[] DrainOutput(Stream source,int maximum)
        {
            using(MemoryStream output=new MemoryStream()) {
                byte[] part=new byte[4096];while(true) {int count=source.Read(part,0,Math.Min(part.Length,maximum-(int)output.Length+1));if(count==0) return output.ToArray();
                    if(output.Length+count>maximum) throw new InvalidDataException("Actual owned import controller output exceeded its closed bound.");output.Write(part,0,count);}
            }
        }
    }

    internal static class HostedHostResources
    {
        [StructLayout(LayoutKind.Sequential)] private struct Memory {public uint Length,Load;public ulong Total,Available,TotalPage,AvailablePage,TotalVirtual,AvailableVirtual,Extended;}
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GlobalMemoryStatusEx(ref Memory memory);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeWaitHandle OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetProcessTimes(SafeWaitHandle process,out long created,out long exited,out long kernel,out long user);
        internal static ulong BootCreation()
        {
            // This is an immutable kernel process-object generation, NOT UTC.
            // Windows' reserved System process (PID4) spans one host boot. An
            // unavailable/zero observation refuses recovery, never invents one.
            FixedServiceIdentity.Require();using(SafeWaitHandle system=OpenProcess(0x1000,false,4)) {
                long created,exited,kernel,user;if(system.IsInvalid || !GetProcessTimes(system,out created,out exited,out kernel,out user) || created<=0)
                    throw new SecurityException("Actual kernel System-process boot generation is unavailable.");return (ulong)created;
            }
        }
        internal static void Check(ulong minimum)
        {
            Memory memory=new Memory {Length=(uint)Marshal.SizeOf(typeof(Memory))};
            if(!GlobalMemoryStatusEx(ref memory) || memory.Available<minimum) throw new IOException("Actual Windows host memory headroom is insufficient for this fixed deployment profile.");
        }
    }

    internal sealed class HostedClientInputs : IDisposable
    {
        internal readonly byte[] Description,Signature,Acceptance;internal readonly ReleaseDescriptor Release;internal readonly TrustChange Trust;
        private PlatformInputLease archiveLease;private FileStream archive;private string generation;
        internal HostedClientInputs(string command,string[] arguments)
        {
            if(command=="trust" || command=="trust-prepare" || command=="trust-finalize" || command=="trust-cancel" || command=="trust-quarantine") {
                using(PlatformInputLease description=PlatformInputLease.Acquire(arguments[1])) using(PlatformInputLease signature=PlatformInputLease.Acquire(arguments[2])) using(PlatformInputLease acceptance=PlatformInputLease.Acquire(arguments[3])) {
                    Description=description.Capture(1,3072);Signature=signature.Capture(64,64);Acceptance=acceptance.Capture(64,64);Trust=TrustChange.Decode(Description);return;
                }
            }
            if(command!="import" && command!="activate" && command!="release-review" && command!="reconcile" && command!="abandon") return;
            using(PlatformInputLease description=PlatformInputLease.Acquire(arguments[1])) using(PlatformInputLease signature=PlatformInputLease.Acquire(arguments[2])) {
                Description=description.Capture(1,60000);Signature=signature.Capture(64,64);Release=ReleaseDescriptor.Decode(Description);
            }
            if(command=="import") {
                try {archiveLease=PlatformInputLease.Acquire(arguments[3]);archive=new FileStream(arguments[3],FileMode.Open,FileAccess.Read,FileShare.Read);
                    if(archive.Length!=Release.ArchiveBytes) throw new SecurityException("Selected archive length differs from its publisher-signed release.");archiveLease.Check();
                } catch {Dispose();throw;}
            }
        }
        internal void Reviewed(string command,byte[] exact)
        {
            if(command=="trust" || command=="trust-prepare" || command=="trust-finalize" || command=="trust-cancel" || command=="trust-quarantine") {
                using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-trust-review-v1")) {
                    if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(Description) || !Wire.Equal(reader.Fixed(64),Signature) || !Wire.Equal(reader.Fixed(64),Acceptance)) throw new SecurityException("Trust review substituted the selected exact transition or key proofs.");
                    Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);if(Wire.Hex(reader.Fixed(32))!=Trust.Previous) throw new SecurityException("Trust review predecessor differs from the selected transition.");reader.End();
                }
            } else if(command=="import" || command=="activate") {
                using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-deployment-admission-v1")) {
                    DeploymentEvent admitted=DeploymentEvent.Decode(reader.Blob(4096));byte[] signature=reader.Fixed(64);reader.Fixed(32);reader.End();
                    if(admitted.Purpose!=(command=="import"?1:2) || admitted.ReleaseSha256!=Wire.Hash(Description) || admitted.ReleaseSequence!=Release.Sequence ||
                        admitted.Controller!=0 || !Wire.Equal(signature,Signature)) throw new SecurityException("Service review substituted the exact selected release, purpose or signature.");generation=admitted.Generation;
                }
            } else if(command=="release-review") {
                using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-release-review-v1")) {
                    if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(Description) || !Wire.Equal(reader.Fixed(64),Signature)) throw new SecurityException("Release review substituted the original selected input.");reader.Fixed(32);reader.End();
                }
            } else if(command=="reconcile" || command=="abandon") {
                using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-deployment-recovery-v1")) {
                    DeploymentEvent admitted=DeploymentEvent.Decode(reader.Blob(4096));byte[] signature=reader.Fixed(64);reader.Fixed(32);byte abandoned=reader.U8();reader.End();
                    if(admitted.ReleaseSha256!=Wire.Hash(Description) || admitted.ReleaseSequence!=Release.Sequence || abandoned!=(command=="abandon"?1:0) || !Wire.Equal(signature,Signature))
                        throw new SecurityException("Recovery review changed source, publisher signature or abandonment intent.");
                }
            }
        }
        internal byte[] PackagePart(byte[] payload)
        {
            if(archive==null || generation==null) throw new SecurityException("Archive transfer has no exact original-client import review.");
            ulong offset;uint count;using(Wire.Reader reader=new Wire.Reader(payload,"luma-windows-hosted-package-next-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=generation) throw new SecurityException("Package request changed its reviewed resource generation.");offset=reader.U64();count=reader.U32();reader.End();
            }
            if(offset!=(ulong)archive.Position || offset>=(ulong)Release.ArchiveBytes || count!=(uint)Math.Min(32768,Release.ArchiveBytes-(long)offset)) throw new SecurityException("Package request is not the exact finite sequential source.");
            archiveLease.Check();byte[] bytes=new byte[count];int at=0;while(at<bytes.Length) {int read=archive.Read(bytes,at,bytes.Length-at);if(read==0) throw new EndOfStreamException("Selected package source truncated.");at+=read;}archiveLease.Check();
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-package-part-v1")) {writer.Fixed(Wire.Bytes(generation,32,true),32);writer.U64(offset);writer.Blob(bytes,32768);return writer.Bytes();}
        }
        public void Dispose() {if(archive!=null) {archive.Dispose();archive=null;}if(archiveLease!=null) {archiveLease.Dispose();archiveLease=null;}}
    }

    internal static partial class HostedCoordinator
    {
        private static string Ticket(string prefix,string digest) {Wire.Bytes(digest,32,true);return "ticket-"+prefix+"-"+digest+".bin";}
        private static void SaveTicket(PrivateState state,string leaf,byte[] bytes,Action check)
        {
            check();if(state.Exists(leaf)) {if(!Wire.Equal(state.Read(leaf,1,60000),bytes)) throw new SecurityException("Immutable signed release input was substituted.");}
            else {check();state.WriteNew(leaf,bytes);}
        }
        private static void Candidate(ReleaseDescriptor release,DeploymentHistory state)
        {
            if(state.Pending!=null) throw new SecurityException("A prior deployment generation is outstanding; no concurrent admission or assumed resource release.");
            if(release.Sequence!=(state.Active==null?1:checked(state.Active.ReleaseSequence+1)) ||
                release.PreviousReleaseSha256!=(state.Active==null?new string('0',64):state.Active.ReleaseSha256)) throw new SecurityException("Publisher release does not extend the exact activated generation/predecessor floor.");
        }
        private static string ProbePayload(AuthorityIdentity identity,DeploymentEvent admission)
        {
            const string source="Luma hosted confinement probe\n";string owner=Wire.Hash(Encoding.ASCII.GetBytes("luma-windows-hosted-untrusted-probe-owner-v1"));
            string workflow=Wire.Hash(Encoding.ASCII.GetBytes("luma-windows-hosted-unexecuted-probe-v1")),digest=Wire.Hash(Encoding.UTF8.GetBytes(source));
            return "{\"schema_version\":1,\"binding\":{\"installation\":\""+identity.Installation+"\",\"owner\":\""+owner+
                "\",\"owner_generation\":1},\"artifact_id\":\"hosted-confinement-probe\",\"format\":\"utf8-text\",\"content\":\"Luma hosted confinement probe\\n\",\"provenance\":{\"request_id\":\""+
                admission.Generation+"\",\"workflow_sha256\":\""+workflow+"\",\"source_sha256\":\""+digest+"\",\"origin\":\"managed\"}}";
        }
        private static void ImportOrActivate(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,bool activate)
        {
            byte[] description=request.Blob(60000),signature=request.Fixed(64);request.End();ReleaseDescriptor release=ReleaseDescriptor.Decode(description);string releaseHash=Wire.Hash(description);
            Stopwatch age=Stopwatch.StartNew();Action original=delegate {
                running();actor.Check();if(age.Elapsed.TotalSeconds>=1800) throw new SecurityException("Separate finite deployment action expired; no ordinary-purpose or extended fallback.");
            };
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                JournalHistory journal=authority.Journal.Read(original);journal.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(journal,original);Candidate(release,state);
                release.Verify(authority.Trust.ForRelease(),signature);HostedReleaseLease utc=new HostedReleaseLease(pipe,authority,release,signature,original);utc.Check();
                DeploymentEvent imported=state.Imported(releaseHash);
                if(activate && imported==null) throw new SecurityException("Activation requires an exact genuinely imported signed package.");
                if(!activate && imported!=null) throw new SecurityException("Release is already imported; use its separate activation action.");
                string generation=Wire.Hex(Wire.Random(32)),leaf=activate?imported.PackageLeaf:"ticket-package-"+Wire.Hex(Wire.Random(16))+".tar";
                DeploymentEvent admission=new DeploymentEvent(activate?(byte)2:(byte)1,releaseHash,release.Sequence,generation,HostedHostResources.BootCreation(),leaf,0,0,0,new string('0',64));
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-deployment-admission-v1")) {
                    exact.Blob(admission.Encode(),4096);exact.Fixed(signature,64);exact.Fixed(Wire.Bytes(journal.Head,32,true),32);
                    Review(pipe,activate?"activate":"import",exact.Bytes(),"Separate 30-minute "+(activate?"activation":"import")+" action; actual original Admin "+actor.Sid+
                        "\nDescriptor SHA256: "+releaseHash+"\nRelease: "+release.Sequence+"\nRootfs SHA256: "+release.RootfsSha256+"\nOwned slot: "+HostedGuestRunner.Distribution(authority.Identity,admission)+
                        "\nGeneration: "+generation+"\nOnly fixed compute-only profile2 is admitted; no Linux identity/grants/TPM/product authority, production qualification or default-distribution change.",utc.CheckObserved);
                }
                utc.Check();HostedHostResources.Check(1536UL*1024*1024);authority.State.Check();
                SaveTicket(authority.State,Ticket("r",releaseHash),description,utc.Check);SaveTicket(authority.State,Ticket("s",releaseHash),signature,utc.Check);
                authority.Journal.Append(activate?JournalKind.ActivationPrepared:JournalKind.ImportPrepared,actor.Sid,admission.Encode(),utc.Check);
                Action live=delegate {original();authority.State.Check();utc.Check();HostedHostResources.Check(256UL*1024*1024);};
                DeploymentEvent started=null;
                Action<OwnedWindowsProcess> register=delegate(OwnedWindowsProcess controller) {
                    live();if(started!=null) throw new SecurityException("A previous original controller lacks a genuine completion.");
                    DeploymentEvent value=admission.WithController(controller.Id,controller.Creation,0,new string('0',64));
                    authority.Journal.Append(JournalKind.ControllerStarted,actor.Sid,value.Encode(),live);started=value;
                };
                Action<string> complete=delegate(string observation) {
                    live();if(started==null || !OwnedWindowsProcess.OriginalExited(started.Controller,started.ControllerCreation)) throw new SecurityException("Original registered controller has not actually exited.");
                    authority.Journal.Append(JournalKind.ControllerCompleted,actor.Sid,started.WithController(started.Controller,started.ControllerCreation,1,observation).Encode(),live);started=null;
                };
                using(StagedPackage package=activate?authority.State.OpenPackage(leaf,release.ArchiveBytes,release.RootfsSha256,live):authority.State.CapturePackage(leaf,release.ArchiveBytes,release.RootfsSha256,delegate(long offset) {
                    live();Action observed=delegate {original();authority.State.Check();utc.CheckObserved();HostedHostResources.Check(256UL*1024*1024);};
                    using(Wire.Writer next=new Wire.Writer("luma-windows-hosted-package-next-v1")) {next.Fixed(Wire.Bytes(generation,32,true),32);next.U64((ulong)offset);next.U32((uint)Math.Min(32768,release.ArchiveBytes-offset));Reply(pipe,"package-next",next.Bytes(),observed);}
                    byte[] frame=HostedPipe.Read(pipe,observed,TimeSpan.FromSeconds(30));using(Wire.Reader part=new Wire.Reader(frame,"luma-windows-hosted-package-part-v1")) {
                        if(Wire.Hex(part.Fixed(32))!=generation || part.U64()!=(ulong)offset) throw new SecurityException("Original package stream generation or offset changed.");byte[] data=part.Blob(32768);part.End();return data;
                    }
                },live)) {
                    PackageContent inspected=PackageInspector.Validate(package.Path,release.ArchiveBytes,release.ContentBytes,release.MemberCount,release.RootfsSha256,release.RequiredFiles,live);
                    PackageInspector.ValidateHostedProfile(inspected,release.RequiredFiles);live();
                    if(activate) {
                        using(HostedGuestDirectory directory=HostedGuestDirectory.Open(authority.Identity,admission,false)) {
                            directory.Check();HostedWslConfiguration.RequireClosed(authority.Identity,actor,admission);
                            byte[] data=HostedGuestRunner.Compute(authority.Identity,actor,admission,new GuestComputeRequest("capture",ProbePayload(authority.Identity,admission)),register,live);
                            string digest;using(SHA256 hash=SHA256.Create()) digest=Wire.Hex(hash.ComputeHash(data));complete(digest);directory.Check();
                            authority.Journal.Append(JournalKind.Activated,actor.Sid,admission.WithController(0,0,1,digest).Encode(),live);
                        }
                    } else {
                        if(new DriveInfo(System.IO.Path.GetPathRoot(authority.State.DirectoryPath)).AvailableFreeSpace<checked(release.ContentBytes*3+1024L*1024*1024)) throw new IOException("Actual NTFS space is insufficient for the bounded new guest image.");
                        using(HostedGuestDirectory directory=HostedGuestDirectory.Open(authority.Identity,admission,true)) {
                            string observation=HostedImportProcess.Run(authority.Identity,actor,admission,directory,package,register,live);complete(observation);
                            HostedWslConfiguration.ConfigureNew(authority.Identity,actor,admission,live);HostedGuestRunner.Drain(authority.Identity,actor,admission,live);directory.Check();
                            authority.Journal.Append(JournalKind.Imported,actor.Sid,admission.WithController(0,0,1,observation).Encode(),live);
                        }
                    }
                }
                JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory verified=DeploymentHistory.Replay(completed,live);
                if(verified.Pending!=null || (activate?(verified.Active==null || verified.Active.ReleaseSha256!=releaseHash):verified.Imported(releaseHash)==null)) throw new SecurityException("Actual durable deployment completion did not reconstruct.");
                using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-deployment-result-v1")) {
                    result.U8(activate?(byte)2:(byte)1);result.Fixed(Wire.Bytes(releaseHash,32,true),32);result.U64(release.Sequence);result.Fixed(Wire.Bytes(completed.Head,32,true),32);
                    result.U8(0);result.U8(0);Reply(pipe,"deployment-observed",result.Bytes(),live);
                }
            }
        }
        private static void ReconcileDeployment(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,bool abandon)
        {
            byte[] description=request.Blob(60000),signature=request.Fixed(64);request.End();ReleaseDescriptor release=ReleaseDescriptor.Decode(description);string digest=Wire.Hash(description);
            Stopwatch age=Stopwatch.StartNew();Action original=delegate {running();actor.Check();if(age.Elapsed.TotalSeconds>=(abandon?30:1800)) throw new SecurityException("Fresh exact recovery action expired.");};
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                JournalHistory journal=authority.Journal.Read(original);journal.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(journal,original);
                DeploymentEvent admission=state.Pending;if(admission==null || admission.ReleaseSha256!=digest || admission.ReleaseSequence!=release.Sequence) throw new SecurityException("No exact outstanding deployment exists for this recovery.");
                AuthorityIdentity verifier=abandon?authority.Trust.ForCleanup(admission.Generation):authority.Trust.ForRelease();release.Verify(verifier,signature);
                HostedReleaseLease utc=abandon?HostedReleaseLease.ForAbandonment(pipe,authority,release,signature,original,verifier):new HostedReleaseLease(pipe,authority,release,signature,original);utc.Check();
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-deployment-recovery-v1")) {
                    exact.Blob(admission.Encode(),4096);exact.Fixed(signature,64);exact.Fixed(Wire.Bytes(journal.Head,32,true),32);exact.U8(abandon?(byte)1:(byte)0);
                    Review(pipe,abandon?"abandon":"reconcile",exact.Bytes(),(abandon?"Abandon and quarantine":"Continue only a genuinely evidenced")+" exact generation "+admission.Generation+
                        "\nDescriptor SHA256: "+digest+"\nOwned slot: "+HostedGuestRunner.Distribution(authority.Identity,admission)+
                        "\nNo import is automatically replayed. Unknown import success is never inferred from a partial boot. No distributions or artifacts are deleted, unregistered or name-killed; previous active slot remains unchanged on abandonment.",utc.CheckObserved);
                }
                Action live=delegate {original();authority.State.Check();utc.Check();};live();
                bool registered=HostedWslConfiguration.Registered(authority.Identity,actor,admission);ulong currentBoot=HostedHostResources.BootCreation();
                if(state.Worker!=null) {
                    if(!OwnedWindowsProcess.OriginalExited(state.Worker.Controller,state.Worker.ControllerCreation)) throw new SecurityException("Original controller still exists; resource generation remains held.");
                    if(admission.Purpose==1 && !abandon) throw new SecurityException("Unknown import exit is not successful import evidence. Use explicit quarantine after a genuine host reboot, not replay.");
                    if(admission.Purpose==1 && currentBoot==admission.HostBootCreation) throw new SecurityException("Unobserved import may still have asynchronous work; actual host reboot proof is required before quarantine.");
                    if(registered) HostedGuestRunner.Drain(authority.Identity,actor,admission,live);
                    else if(admission.Purpose!=1 || currentBoot==admission.HostBootCreation) throw new SecurityException("Absent slot is not sufficient current-boot drain evidence.");
                    string proof=Wire.Hash(Encoding.ASCII.GetBytes("luma-observed-original-controller-exit-and-drain-v1\n"+admission.Generation+"\n"+currentBoot.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                    authority.Journal.Append(JournalKind.ControllerCompleted,actor.Sid,state.Worker.WithController(state.Worker.Controller,state.Worker.ControllerCreation,2,proof).Encode(),live);
                    state=DeploymentHistory.Replay(authority.Journal.Read(live),live);
                }
                if(abandon) {
                    if(state.CompletedControllers!=0 && registered) HostedGuestRunner.Drain(authority.Identity,actor,admission,live);
                    if(admission.Purpose==1 && state.CompletedControllers!=0 && state.SuccessfulControllers==0 && currentBoot==admission.HostBootCreation)
                        throw new SecurityException("Unknown import is still quarantined pending genuine host reboot/drain evidence.");
                    string proof=Wire.Hash(Encoding.ASCII.GetBytes("luma-quarantine-no-replay-no-delete-v1\n"+admission.Generation+"\n"+currentBoot.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                    authority.Journal.Append(JournalKind.Cancelled,actor.Sid,admission.WithController(0,0,2,proof).Encode(),live);
                } else if(admission.Purpose==1) {
                    if(state.SuccessfulControllers<1 || state.LastSuccess==null || !registered) throw new SecurityException("Recovery has no durable actual successful import-controller evidence.");
                    using(HostedGuestDirectory directory=HostedGuestDirectory.Open(authority.Identity,admission,false)) {
                        HostedWslConfiguration.ConfigureNew(authority.Identity,actor,admission,live);HostedGuestRunner.Drain(authority.Identity,actor,admission,live);directory.Check();
                        authority.Journal.Append(JournalKind.Imported,actor.Sid,admission.WithController(0,0,1,state.LastSuccess.ObservationSha256).Encode(),live);
                    }
                } else {
                    if(!registered) throw new SecurityException("Activation recovery slot is absent; never invent successful installation.");
                    using(StagedPackage package=authority.State.OpenPackage(admission.PackageLeaf,release.ArchiveBytes,release.RootfsSha256,live))
                    using(HostedGuestDirectory directory=HostedGuestDirectory.Open(authority.Identity,admission,false)) {
                        PackageContent inspected=PackageInspector.Validate(package.Path,release.ArchiveBytes,release.ContentBytes,release.MemberCount,release.RootfsSha256,release.RequiredFiles,live);
                        PackageInspector.ValidateHostedProfile(inspected,release.RequiredFiles);HostedWslConfiguration.RequireClosed(authority.Identity,actor,admission);
                        DeploymentEvent started=null;
                        byte[] data=HostedGuestRunner.Compute(authority.Identity,actor,admission,new GuestComputeRequest("capture",ProbePayload(authority.Identity,admission)),delegate(OwnedWindowsProcess controller) {
                            started=admission.WithController(controller.Id,controller.Creation,0,new string('0',64));authority.Journal.Append(JournalKind.ControllerStarted,actor.Sid,started.Encode(),live);
                        },live);
                        if(started==null || !OwnedWindowsProcess.OriginalExited(started.Controller,started.ControllerCreation)) throw new SecurityException("New exact recovery probe controller exit is unobserved.");
                        string proof;using(SHA256 hash=SHA256.Create()) proof=Wire.Hex(hash.ComputeHash(data));
                        authority.Journal.Append(JournalKind.ControllerCompleted,actor.Sid,started.WithController(started.Controller,started.ControllerCreation,1,proof).Encode(),live);directory.Check();
                        authority.Journal.Append(JournalKind.Activated,actor.Sid,admission.WithController(0,0,1,proof).Encode(),live);
                    }
                }
                JournalHistory final=authority.Journal.Read(live);final.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory rebuilt=DeploymentHistory.Replay(final,live);
                if(rebuilt.Pending!=null) throw new SecurityException("Exact recovery remains outstanding; no resource release is claimed.");
                using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-deployment-reconciled-v1")) {
                    result.U8(abandon?(byte)1:(byte)0);result.Fixed(Wire.Bytes(digest,32,true),32);result.U64(release.Sequence);result.Fixed(Wire.Bytes(final.Head,32,true),32);result.U8(0);result.U8(0);Reply(pipe,"deployment-reconciled",result.Bytes(),live);
                }
            }
        }
    }
}
