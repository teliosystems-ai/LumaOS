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
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Luma.Windows;

namespace Luma.Windows.Hosted
{
    // Data delivered to this original client, never a server write capability.
    internal sealed class HostedManualSnapshot : IDisposable
    {
        internal readonly EnrolledReadIntent Intent;private byte[] content;private bool used;
        private HostedManualSnapshot(HostedReadInputs read) {Intent=read.Intent;content=read.TakeCompletedForManualSave();}
        internal static HostedManualSnapshot FromCompleted(HostedReadInputs read) {if(read==null) throw new ArgumentNullException("read");return new HostedManualSnapshot(read);}
        internal byte[] Consume() {
            if(used || content==null) throw new SecurityException("The completed manual snapshot was consumed or cleared; no replay is allowed.");
            using(SHA256 hash=SHA256.Create()) if(content.Length!=Intent.Bytes || Wire.Hex(hash.ComputeHash(content))!=Intent.Sha256) throw new SecurityException("The whole completed snapshot changed before manual save.");
            used=true;byte[] result=content;content=null;return result;
        }
        public void Dispose() {used=true;if(content!=null) {Array.Clear(content,0,content.Length);content=null;}}
    }

    // Filesystem mechanism only. The joined original client supplies current
    // actor, cancellation, elapsed-purpose and actual encryption checks. This
    // type cannot grant a native product Export or change the service journal.
    internal sealed class HostedManualTarget : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [StructLayout(LayoutKind.Sequential)] private struct Attributes {public uint Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)] public bool Inherit;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint sharing,IntPtr attributes,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint sharing,ref Attributes attributes,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out Information information);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetFileType(SafeFileHandle file);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint maximum,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file,StringBuilder name,uint size,out uint serial,out uint maximum,out uint flags,StringBuilder format,uint formatSize);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CancelIoEx(SafeFileHandle file,IntPtr overlapped);
        private sealed class Node {internal SafeFileHandle Handle;internal string Path;internal Information Identity;internal byte[] Security;}
        private readonly List<Node> parents=new List<Node>();private readonly Action original;private Action additional;private readonly string path,owner;private FileStream stream;private Information created;private byte[] fileSecurity;private bool attempted;
        internal string Parent {get{return Path.GetDirectoryName(path);}}
        internal uint Volume {get{return parents[parents.Count-1].Identity.Volume;}}
        internal string PathName {get{return path;}}
        internal HostedManualTarget(string path,string owner,Action original) {
            if(original==null) throw new ArgumentNullException("original");this.path=PlatformInputLease.ValidatePath(path);this.owner=Wire.Sid(owner);this.original=original;
            try {
                string[] parts=path.Substring(3).Split('\\');if(parts.Length>32) throw new SecurityException("Manual target exceeds held ancestor bound.");
                string current=path.Substring(0,3);OpenParent(current);for(int index=0;index<parts.Length-1;index++) {current=Path.Combine(current,parts[index]);OpenParent(current);}Check();
            }catch {Dispose();throw;}
        }
        private static Information Inspect(SafeFileHandle file,bool directory,string path) {
            Information value;if(GetFileType(file)!=1 || !GetFileInformationByHandle(file,out value)) throw new IOException("Manual target requires an actual local disk object.");
            if(((value.Attributes&0x10U)!=0)!=directory || (value.Attributes&(0x400U|0x1000U|0x40000U|0x80000U|0x100000U|0x400000U))!=0 || !directory && value.Links!=1) throw new SecurityException("Manual target is linked, reparse, recalled, cloud/offline or the wrong type.");
            StringBuilder final=new StringBuilder(512);uint count=GetFinalPathNameByHandle(file,final,512,0);
            if(count==0 || count>=512 || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Manual target handle selected another exact path.");
            StringBuilder name=new StringBuilder(256),format=new StringBuilder(32);uint serial,maximum,flags;
            if(!GetVolumeInformationByHandleW(file,name,256,out serial,out maximum,out flags,format,32) || format.ToString()!="NTFS" || serial!=value.Volume) throw new SecurityException("Manual private target requires observed local NTFS.");return value;
        }
        private static byte[] Security(SafeFileHandle file) {
            IntPtr owner,group,dacl,sacl,descriptor;uint status=GetSecurityInfo(file,1,7,out owner,out group,out dacl,out sacl,out descriptor);if(status!=0) throw new Win32Exception((int)status);
            try {uint count=GetSecurityDescriptorLength(descriptor);if(count<20 || count>65536 || owner==IntPtr.Zero || dacl==IntPtr.Zero) throw new SecurityException("Manual target security is missing or unbounded.");byte[] result=new byte[count];Marshal.Copy(descriptor,result,0,(int)count);return result;}finally {LocalFree(descriptor);}
        }
        private static bool Same(Information left,Information right) {return left.Attributes==right.Attributes && left.Volume==right.Volume && left.IndexHigh==right.IndexHigh && left.IndexLow==right.IndexLow && left.Creation.dwHighDateTime==right.Creation.dwHighDateTime && left.Creation.dwLowDateTime==right.Creation.dwLowDateTime;}
        private void OpenParent(string selected) {
            original();SafeFileHandle handle=CreateFile(selected,0x20080U,3,IntPtr.Zero,3,0x02300000U,IntPtr.Zero);
            try {if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());Information value=Inspect(handle,true,selected);
                if(parents.Count!=0 && value.Volume!=parents[0].Identity.Volume) throw new SecurityException("Manual target crossed a held volume.");
                parents.Add(new Node {Handle=handle,Path=selected,Identity=value,Security=Security(handle)});
            }catch {handle.Dispose();throw;}
        }
        internal void Check() {
            original();if(additional!=null) additional();if(parents.Count==0) throw new ObjectDisposedException("HostedManualTarget");
            foreach(Node node in parents) {if(!Same(node.Identity,Inspect(node.Handle,true,node.Path)) || !Wire.Equal(node.Security,Security(node.Handle))) throw new SecurityException("Held manual target ancestor identity or owner/DACL changed.");original();}
            if(stream!=null) {Information now=Inspect(stream.SafeFileHandle,false,path);if(!Same(created,now) || now.Volume!=Volume || !Wire.Equal(fileSecurity,Security(stream.SafeFileHandle))) throw new SecurityException("Exclusive manual output identity or owner/DACL changed.");}if(additional!=null) additional();original();
        }
        internal void RequireAdditionalChecks(Action check) {if(check==null || additional!=null || attempted) throw new SecurityException("Manual target protection check can only be installed once before use.");additional=check;Check();}
        internal byte[] Fingerprint() {
            Check();using(Wire.Writer writer=new Wire.Writer("luma-windows-manual-target-v1")) {writer.Text(path,1024);writer.Text(owner,184);writer.U8((byte)parents.Count);
                foreach(Node node in parents) {writer.U32(node.Identity.Volume);writer.U32(node.Identity.IndexHigh);writer.U32(node.Identity.IndexLow);writer.U32(unchecked((uint)node.Identity.Creation.dwHighDateTime));writer.U32(unchecked((uint)node.Identity.Creation.dwLowDateTime));writer.Fixed(Wire.HashBytes(node.Security),32);}return writer.Bytes();}
        }
        internal string Review(EnrolledReadIntent intent,byte[] actor,byte[] nonce) {
            if(intent==null || intent.Owner!=owner || actor==null || actor.Length<1 || actor.Length>512 || nonce==null || nonce.Length!=32) throw new SecurityException("Manual save review requires the original source owner, current actor and a fresh exact nonce.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-manual-save-review-v1")) {writer.Blob(intent.Encode(),2048);writer.Blob(Fingerprint(),8192);writer.Blob(actor,512);writer.Fixed(nonce,32);return Wire.Hash(writer.Bytes());}
        }
        private void NewFile() {
            RawSecurityDescriptor security=new RawSecurityDescriptor("O:"+owner+"G:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)");byte[] descriptor=new byte[security.BinaryLength];security.GetBinaryForm(descriptor,0);
            IntPtr data=Marshal.AllocHGlobal(descriptor.Length);SafeFileHandle file=null;
            try {Marshal.Copy(descriptor,0,data,descriptor.Length);Attributes attributes=new Attributes {Length=(uint)Marshal.SizeOf(typeof(Attributes)),Descriptor=data,Inherit=false};
                file=CreateFile(path,0xc0020080U,0,ref attributes,1,0xc0300000U,IntPtr.Zero);if(file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                created=Inspect(file,false,path);if(created.Volume!=Volume || created.SizeHigh!=0 || created.SizeLow!=0) throw new SecurityException("New exclusive output differs from its held target.");
                fileSecurity=Security(file);RawSecurityDescriptor actual=new RawSecurityDescriptor(fileSecurity,0);
                if(actual.Owner.Value!=owner || (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 || actual.DiscretionaryAcl==null || actual.DiscretionaryAcl.Count!=2) throw new SecurityException("New output is not owner/SYSTEM-only private storage.");
                foreach(GenericAce entry in actual.DiscretionaryAcl) {CommonAce ace=entry as CommonAce;if(ace==null || ace.AceType!=AceType.AccessAllowed || ace.AceFlags!=AceFlags.None || ace.AccessMask!=0x1f01ff || ace.SecurityIdentifier.Value!=owner && ace.SecurityIdentifier.Value!="S-1-5-18") throw new SecurityException("New output ACL differs from exact private owner/SYSTEM creation.");}
                stream=new FileStream(file,FileAccess.ReadWrite,32768,true);file=null;Check();
            }finally {Marshal.FreeHGlobal(data);if(file!=null) file.Dispose();}
        }
        private void Await(Task task) {
            try {while(!task.Wait(100)) Check();task.GetAwaiter().GetResult();Check();}
            catch {if(stream!=null) {CancelIoEx(stream.SafeFileHandle,IntPtr.Zero);try {if(!task.Wait(2000)) stream.Dispose();}catch(AggregateException) {}}throw;}
        }
        internal void Save(HostedManualSnapshot snapshot,string confirmation,byte[] actor,byte[] nonce) {
            if(attempted) throw new SecurityException("Manual target cannot replay an attempted save.");
            if(snapshot==null || confirmation!=Review(snapshot.Intent,actor,nonce)) throw new SecurityException("Independent exact original-client save was not confirmed.");
            attempted=true;byte[] bytes=snapshot.Consume();
            try {Check();NewFile();for(int offset=0;offset<bytes.Length;offset+=32768) {Check();Await(stream.WriteAsync(bytes,offset,Math.Min(32768,bytes.Length-offset)));}
                Check();Await(Task.Factory.StartNew(delegate {stream.Flush(true);}));stream.Position=0;byte[] read=new byte[32768];
                try {using(SHA256 hash=SHA256.Create()) {int total=0;while(total<bytes.Length) {Check();Task<int> pending=stream.ReadAsync(read,0,Math.Min(read.Length,bytes.Length-total));Await(pending);int count=pending.GetAwaiter().GetResult();if(count<1) throw new EndOfStreamException("Manual save full readback was truncated.");hash.TransformBlock(read,0,count,read,0);total+=count;}hash.TransformFinalBlock(new byte[0],0,0);
                    if(stream.Length!=bytes.Length || Wire.Hex(hash.Hash)!=snapshot.Intent.Sha256) throw new SecurityException("Manual save whole-file readback differs from the reviewed completed snapshot.");}}
                finally {Array.Clear(read,0,read.Length);}Check();
            }finally {Array.Clear(bytes,0,bytes.Length);}
        }
        public void Dispose() {try {if(stream!=null) {stream.Dispose();stream=null;}}finally {foreach(Node node in parents) node.Handle.Dispose();parents.Clear();}}
    }

    internal static partial class HostedAuthorityProgram
    {
        private static HostedManualSnapshot ManualRead(HostedReadInputs input,HostedClientIdentity actor) {
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",HostedPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)) {
                Stopwatch age=Stopwatch.StartNew();Action check=delegate {actor.Check();input.Check();HostedPipe.CheckServer(pipe);if(age.Elapsed>=TimeSpan.FromSeconds(30)) throw new SecurityException("Independent original Read expired; no complete manual snapshot is inferred.");};
                actor.Check();pipe.Connect(3000);check();IngestionHello(pipe,check);
                using(Wire.Writer request=new Wire.Writer("luma-windows-hosted-request-v1")) {request.Text("read-enrolled-file",32);request.Blob(input.Intent.Encode(),2048);HostedPipe.Write(pipe,request.Bytes(),check,TimeSpan.FromSeconds(30));}
                while(true) {byte[] response=HostedPipe.Read(pipe,check,TimeSpan.FromSeconds(30));try {using(Wire.Reader frame=new Wire.Reader(response,"luma-windows-hosted-response-v1")) {
                    string kind=frame.Text(32);byte[] payload=frame.Blob(60000);frame.End();try {
                        if(kind=="refused") throw new SecurityException("Actual original Read refused; no write or completed snapshot is inferred.");
                        if(kind=="utc-challenge") {HostedTimeEndpoint.Deliver(pipe,payload,Wire.Hash(input.Intent.Encode()),check);continue;}
                        if(kind=="review") {IngestionConfirm(pipe,payload,"read-enrolled-file",input.Reviewed,check,age,TimeSpan.FromSeconds(30));continue;}
                        if(kind=="read-chunk") {byte[] ack=input.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                        if(kind=="read-completed") {input.Completed(payload);check();return HostedManualSnapshot.FromCompleted(input);}
                        throw new SecurityException("Unexpected frame cannot cross the original Read ceremony.");
                    }finally {Array.Clear(payload,0,payload.Length);}
                }}finally {Array.Clear(response,0,response.Length);}}
            }
        }
        private static int ManualSaveClient(string[] arguments) {
            if(Console.IsInputRedirected || Console.IsOutputRedirected || arguments.Length!=7) throw new SecurityException("Interactive save-enrolled-snapshot INSTALLATION ROOT RELATIVE_PATH EXACT_BYTES SHA256 NEW_ABSOLUTE_TARGET requires separate Read and manual-save confirmations.");
            string[] read=new string[6];Array.Copy(arguments,read,6);read[0]="read-enrolled-file";
            using(HostedClientIdentity actor=new HostedClientIdentity())
            using(HostedReadInputs input=new HostedReadInputs(read,true)) {
                if(input.Intent.Owner!=actor.Sid) throw new SecurityException("Manual Read owner differs from actual original client.");
                using(HostedManualSnapshot snapshot=ManualRead(input,actor)) {
                    Stopwatch age=Stopwatch.StartNew();Action current=delegate {actor.Check();input.Check();if(age.Elapsed>=TimeSpan.FromSeconds(30)) throw new SecurityException("Separate nonrenewable manual-save review expired; a partial new output may remain, never overwritten or automatically deleted.");};
                    using(HostedManualTarget target=new HostedManualTarget(arguments[6],actor.Sid,current)) {
                        HostProtectionSamples protection=new HostProtectionSamples(delegate {return WindowsHostProtection.Observe(target.Parent,actor.Token.DangerousGetHandle());},delegate {return age.ElapsedMilliseconds;});
                        HostProtectionObservation first=protection.Read(true);first.Volume.RequireProtected();string volume=first.Volume.Volume;uint serial=first.Volume.Serial;
                        if(serial!=target.Volume) throw new SecurityException("Protected volume differs from held manual target.");
                        Action protectedVolume=delegate {current();HostProtectionObservation now=protection.Read(false);now.Volume.RequireProtected();if(now.Volume.Volume!=volume || now.Volume.Serial!=serial) throw new SecurityException("Manual target protection/volume changed.");current();};
                        target.RequireAdditionalChecks(protectedVolume);Action admitted=target.Check;
                        byte[] nonce=new byte[32];using(RandomNumberGenerator random=RandomNumberGenerator.Create()) random.GetBytes(nonce);byte[] identity=actor.Fingerprint();
                        string review=target.Review(snapshot.Intent,identity,nonce);admitted();
                        Console.WriteLine("Read COMPLETED and pipe CLOSED. This manual action saves the already-delivered whole snapshot, not a current source version, product Export, Linux grant, citation or model effect.\nExact bytes/SHA256: "+snapshot.Intent.Bytes+" / "+snapshot.Intent.Sha256+"\nNew exclusive owner/SYSTEM-only NTFS target: "+target.PathName+"\nNo overwrite, model, service-side output open or automatic retry/deletion. Source changes/revocation cannot recall bytes already delivered. Cancellation/failure may leave this named partial file; inspect it manually.\nThirty seconds includes this review and save; synchronous kernel/provider hard deadlines and zero-exposure encryption transitions are not claimed.\nConfirm ONLY this independent save: SAVE "+review);
                        if(IngestionLine(admitted,age,TimeSpan.FromSeconds(30))!="SAVE "+review) {Console.WriteLine("Manual save cancelled; no target file was created.");return 0;}
                        admitted();protection.Read(true).Volume.RequireProtected();admitted();
                        target.Save(snapshot,review,identity,nonce);admitted();Console.WriteLine("Saved and flushed exact whole snapshot; complete readback SHA256 matched. No product publication or installed qualification is inferred.");return 0;
                    }
                }
            }
        }
    }
}
