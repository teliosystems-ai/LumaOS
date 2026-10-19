// Test-only executable mechanism fixtures. Never included in the service build.
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Luma.Windows.Hosted;

public static class LumaHostedReadFixture
{
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateHardLink(string path,string existing,IntPtr security);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint create,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool DeviceIoControl(SafeFileHandle file,uint code,byte[] input,int inputCount,IntPtr output,int outputCount,out int returned,IntPtr overlapped);
    private static void Junction(string link,string target) {
        if(Path.GetDirectoryName(link)!=Path.GetDirectoryName(target)) throw new Exception("Fixture junction target must stay in the same disposable directory.");Directory.CreateDirectory(target);Directory.CreateDirectory(link);
        byte[] substitute=Encoding.Unicode.GetBytes(@"\??\"+target),print=Encoding.Unicode.GetBytes(target);byte[] buffer=new byte[20+substitute.Length+print.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(0xa0000003U),0,buffer,0,4);Buffer.BlockCopy(BitConverter.GetBytes((ushort)(buffer.Length-8)),0,buffer,4,2);Buffer.BlockCopy(BitConverter.GetBytes((ushort)substitute.Length),0,buffer,10,2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)(substitute.Length+2)),0,buffer,12,2);Buffer.BlockCopy(BitConverter.GetBytes((ushort)print.Length),0,buffer,14,2);Buffer.BlockCopy(substitute,0,buffer,16,substitute.Length);Buffer.BlockCopy(print,0,buffer,18+substitute.Length,print.Length);
        using(SafeFileHandle handle=CreateFile(link,0x40000000,0,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {int returned;if(handle.IsInvalid || !DeviceIoControl(handle,0x900a4,buffer,buffer.Length,IntPtr.Zero,0,out returned,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());}
        Require((File.GetAttributes(link)&FileAttributes.ReparsePoint)!=0);
    }
    private static readonly BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic;
    private static object Create(string name,params object[] arguments) {
        try {return Activator.CreateInstance(typeof(EnrolledReadIntent).Assembly.GetType("Luma.Windows.Hosted."+name,true),Instance,null,arguments,null);}
        catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}
    }
    private static object Call(object value,string method,params object[] arguments) {
        try {return value.GetType().GetMethod(method,Instance).Invoke(value,arguments);}catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}
    }
    private static void Refuse(Action action) {try {action();}catch(SecurityException) {return;}catch(UnauthorizedAccessException) {return;}catch(InvalidDataException) {return;}throw new Exception("Required closed read refusal did not occur.");}
    private static void KernelRefuse(Action action) {try {action();}catch(IOException) {return;}catch(UnauthorizedAccessException) {return;}throw new Exception("Kernel accepted modification/rename of a held read source.");}
    private static void Require(bool value) {if(!value) throw new Exception("Actual enrolled-read fixture failed.");}
    private static string Hash(byte[] bytes) {using(SHA256 sha=SHA256.Create()) return Wire.Hex(sha.ComputeHash(bytes));}
    private static string H(char value) {return new string(value,64);}
    private static byte[] Review(EnrolledReadIntent intent,byte[] snapshot) {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-review-v1")) {writer.Blob(intent.Encode(),2048);writer.Blob(snapshot,4096);return writer.Bytes();}}
    private static byte[] Ack(string review,string source,uint offset,byte[] data) {
        byte[] hash;using(SHA256 sha=SHA256.Create()) hash=sha.ComputeHash(data,0,(int)offset);using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-read-ack-v1")) {writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(source,32,true),32);writer.U32(offset);writer.Fixed(hash,32);return writer.Bytes();}
    }
    private static string[] Arguments(EnrolledReadIntent intent) {return new string[]{"read-enrolled-file",intent.Installation,intent.Root,intent.RelativePath,intent.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),intent.Sha256};}
    public static int Run(string workspace,AuthorityIdentity identity,Func<byte[],byte[]> timeSign,Func<byte[],byte[]> authoritySign,Func<byte[],byte[]> publisherSign)
    {
        int assertions=0;string sid;using(WindowsIdentity current=WindowsIdentity.GetCurrent()) sid=current.User.Value;
        string parent=Path.Combine(Path.GetFullPath(workspace),".luma"),root=Path.Combine(parent,"windows-read-fixtures-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(parent);
        Require(new DriveInfo(Path.GetPathRoot(root)).DriveFormat=="NTFS" && (File.GetAttributes(parent)&FileAttributes.ReparsePoint)==0);
        DirectorySecurity own=new DirectorySecurity();own.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.CreateDirectory(root,own);
        string stage="intent";try {
            byte[] content=new byte[65537];for(int index=0;index<content.Length;index++) content[index]=(byte)(index%251);string file=Path.Combine(root,"source.bin");File.WriteAllBytes(file,content);
            FileSecurity ownFile=new FileSecurity();ownFile.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(A;;FA;;;"+sid+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);File.SetAccessControl(file,ownFile);
            EnrolledReadIntent intent=new EnrolledReadIntent(identity.Installation,sid,root,"source.bin",content.Length,Hash(content));
            Require(Wire.Equal(intent.Encode(),EnrolledReadIntent.Decode(intent.Encode()).Encode()));intent.Match(identity,sid);assertions++;
            Refuse(delegate {intent.Match(identity,"S-1-5-21-1-2-3-500");});assertions++;
            Refuse(delegate {new EnrolledReadIntent(H('1'),sid,root,"source.bin",content.Length,Hash(content)).Match(identity,sid);});assertions++;
            Refuse(delegate {new EnrolledReadIntent(identity.Installation,sid,root,"..\\source.bin",content.Length,Hash(content));});assertions++;
            Refuse(delegate {new EnrolledReadIntent(identity.Installation,sid,root,"source.bin:stream",content.Length,Hash(content));});assertions++;
            Refuse(delegate {new EnrolledReadIntent(identity.Installation,sid,root,"source.bin",1048577,Hash(content));});assertions++;
            using(Wire.Writer wrong=new Wire.Writer("luma-windows-hosted-read-intent-v1")) {wrong.Text("organize",32);Refuse(delegate {EnrolledReadIntent.Decode(wrong.Bytes());});assertions++;}
            Refuse(delegate {EnrolledReadIntent.Decode(Wire.Join(intent.Encode(),new byte[]{0}));});assertions++;
            // Independent UTC approval is freshness of this source only. It
            // neither creates a reviewed source object nor starts a read grant.
            LiveUtcWindow time=new LiveUtcWindow(identity,Wire.Hash(intent.Encode()),1000,1000000);TimeAttestation proof=new TimeAttestation(identity.Installation,time.Nonce,Wire.Hash(intent.Encode()),2000,2010);time.Accept(proof.Encode(),timeSign(proof.Encode()));time.Check();assertions++;
            LiveUtcWindow wrongSource=new LiveUtcWindow(identity,H('2'),1000,1000000);TimeAttestation substituted=new TimeAttestation(identity.Installation,wrongSource.Nonce,Wire.Hash(intent.Encode()),2000,2010);Refuse(delegate {wrongSource.Accept(substituted.Encode(),timeSign(substituted.Encode()));});assertions++;
            byte[] snapshot;int liveCalls=0;bool revoked=false;Action live=delegate {liveCalls++;if(revoked) throw new SecurityException("Actual mechanism boundary revoked by fixture.");};
            using(WindowsIdentity current=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate|TokenAccessLevels.Impersonate)) {
                stage="actual owner source capture";
                using(IDisposable source=(IDisposable)Create("EnrolledReadSource",intent,current.AccessToken,live)) {
                    snapshot=(byte[])Call(source,"Snapshot");byte[] actual=(byte[])Call(source,"CaptureVerified");try {Require(Wire.Equal(actual,content) && liveCalls>20);}finally {Array.Clear(actual,0,actual.Length);}assertions++;
                    KernelRefuse(delegate {File.WriteAllBytes(file,new byte[]{1});});assertions++;
                    KernelRefuse(delegate {File.Move(file,file+".moved");});assertions++;
                    KernelRefuse(delegate {Directory.Move(root,root+"-moved");});assertions++;
                    Directory.CreateDirectory(Path.Combine(root,"unrelated-child"));Call(source,"Check");assertions++;
                    revoked=true;Refuse(delegate {Call(source,"CaptureVerified");});revoked=false;assertions++;
                }
                EnrolledReadIntent wrongHash=new EnrolledReadIntent(identity.Installation,sid,root,"source.bin",content.Length,H('9'));
                stage="wrong hash/length/token owner";
                using(IDisposable source=(IDisposable)Create("EnrolledReadSource",wrongHash,current.AccessToken,live)) {Refuse(delegate {Call(source,"CaptureVerified");});assertions++;}
                EnrolledReadIntent wrongBytes=new EnrolledReadIntent(identity.Installation,sid,root,"source.bin",content.Length-1,Hash(content));Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",wrongBytes,current.AccessToken,live)) {} });assertions++;
                EnrolledReadIntent wrongOwner=new EnrolledReadIntent(identity.Installation,"S-1-5-21-1-2-3-500",root,"source.bin",content.Length,Hash(content));Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",wrongOwner,current.AccessToken,live)) {} });assertions++;
                stage="actual different NTFS owner (public system metadata only)";
                string publicSystem=Path.Combine(Environment.SystemDirectory,"kernel32.dll");long systemBytes=new FileInfo(publicSystem).Length;Require(systemBytes>0 && systemBytes<=EnrolledReadIntent.MaximumBytes && ((SecurityIdentifier)File.GetAccessControl(publicSystem,AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))).Value!=sid);
                EnrolledReadIntent notOwned=new EnrolledReadIntent(identity.Installation,sid,Environment.SystemDirectory,"kernel32.dll",(int)systemBytes,H('9'));Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",notOwned,current.AccessToken,live)) {} });assertions++;
                FileSecurity before=File.GetAccessControl(file,AccessControlSections.Owner|AccessControlSections.Access);
                stage="file ACL revocation";
                try {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",intent,current.AccessToken,live)) {
                    FileSecurity deny=new FileSecurity();deny.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(D;;0x1;;;"+sid+")(A;;FA;;;"+sid+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);File.SetAccessControl(file,deny);
                    Refuse(delegate {Call(source,"CaptureVerified");});assertions++;
                }}finally {FileSecurity restored=new FileSecurity();restored.SetSecurityDescriptorBinaryForm(before.GetSecurityDescriptorBinaryForm(),AccessControlSections.Owner|AccessControlSections.Access);File.SetAccessControl(file,restored);}
                DirectorySecurity parentBefore=Directory.GetAccessControl(root,AccessControlSections.Owner|AccessControlSections.Access);
                stage="ancestor ACL revocation";
                try {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",intent,current.AccessToken,live)) {
                    DirectorySecurity altered=new DirectorySecurity();altered.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;0x1200a9;;;BU)",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.SetAccessControl(root,altered);
                    Refuse(delegate {Call(source,"Check");});assertions++;
                }}finally {DirectorySecurity restored=new DirectorySecurity();restored.SetSecurityDescriptorBinaryForm(parentBefore.GetSecurityDescriptorBinaryForm(),AccessControlSections.Owner|AccessControlSections.Access);Directory.SetAccessControl(root,restored);}
                string hard=Path.Combine(root,"hard.bin");if(!CreateHardLink(hard,file,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                stage="actual hardlink";
                try {Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",intent,current.AccessToken,live)) {} });assertions++;}finally {File.Delete(hard);}
                FileAttributes attributes=File.GetAttributes(file);try {File.SetAttributes(file,attributes|FileAttributes.Offline);Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",intent,current.AccessToken,live)) {} });assertions++;}finally {File.SetAttributes(file,attributes);}
                stage="actual disposable junction";string link=Path.Combine(root,"junction"),target=Path.Combine(root,"target");
                try {Junction(link,target);EnrolledReadIntent linked=new EnrolledReadIntent(identity.Installation,sid,link,"never-read.bin",1,H('9'));Refuse(delegate {using(IDisposable source=(IDisposable)Create("EnrolledReadSource",linked,current.AccessToken,live)) {} });assertions++;}finally {if(Directory.Exists(link)) Directory.Delete(link,false);}
            }
            stage="delivery protocol";
            string review=H('3'),objectHash=Wire.Hash(snapshot);object delivery=Create("EnrolledReadDelivery",intent,review,objectHash);
            Refuse(delegate {Call(delivery,"Chunk",content,0);});assertions++;
            Refuse(delegate {Call(delivery,"Complete");});assertions++;
            Refuse(delegate {Call(delivery,"Begin",H('4'),objectHash);});assertions++;
            Call(delivery,"Begin",Wire.Hash(intent.Encode()),objectHash);Refuse(delegate {Call(delivery,"Begin",Wire.Hash(intent.Encode()),objectHash);});assertions++;
            byte[] changed=(byte[])content.Clone();changed[0]^=1;Refuse(delegate {Call(delivery,"Chunk",changed,0);});Array.Clear(changed,0,changed.Length);assertions++;
            using(IDisposable client=(IDisposable)Create("HostedReadInputs",Arguments(intent),false)) {
                Refuse(delegate {Call(client,"Part",new byte[]{1});});assertions++;
                Refuse(delegate {Call(client,"Completed",new byte[]{1});});assertions++;
                Call(client,"Reviewed",Review(intent,snapshot),review);Refuse(delegate {Call(client,"Reviewed",Review(intent,snapshot),review);});assertions++;
                byte[] first=(byte[])Call(delivery,"Chunk",content,0);byte[] ack=(byte[])Call(client,"Part",first);Refuse(delegate {Call(client,"Part",first);});assertions++;
                Refuse(delegate {Call(delivery,"Acknowledge",Ack(H('5'),objectHash,32768,content),content);});assertions++;
                Refuse(delegate {Call(delivery,"Acknowledge",Ack(review,H('5'),32768,content),content);});assertions++;
                Refuse(delegate {Call(delivery,"Acknowledge",Ack(review,objectHash,65536,content),content);});assertions++;
                Call(delivery,"Acknowledge",ack,content);Refuse(delegate {Call(delivery,"Acknowledge",ack,content);});assertions++;
                Refuse(delegate {Call(delivery,"Complete");});assertions++;
                Refuse(delegate {Call(delivery,"Chunk",content,0);});assertions++;
                for(int offset=32768;offset<content.Length;offset+=32768) {byte[] chunk=(byte[])Call(delivery,"Chunk",content,offset);byte[] receipt=(byte[])Call(client,"Part",chunk);Call(delivery,"Acknowledge",receipt,content);Array.Clear(chunk,0,chunk.Length);Array.Clear(receipt,0,receipt.Length);}
                byte[] complete=(byte[])Call(delivery,"Complete");byte[] falseAuthority=(byte[])complete.Clone();falseAuthority[falseAuthority.Length-1]=1;Refuse(delegate {Call(client,"Completed",falseAuthority);});assertions++;
                Call(client,"Completed",complete);Require(((string)Call(client,"Summary")).Contains("No file saved"));assertions++;
                Refuse(delegate {Call(delivery,"Complete");});Refuse(delegate {Call(client,"Completed",complete);});Refuse(delegate {Call(delivery,"Chunk",content,0);});assertions++;
                Array.Clear(first,0,first.Length);Array.Clear(ack,0,ack.Length);
            }
            using(IDisposable client=(IDisposable)Create("HostedReadInputs",Arguments(intent),false)) {
                Refuse(delegate {Call(client,"Reviewed",Review(intent,Wire.Join(snapshot,new byte[]{0})),review);});assertions++;
            }
            stage="persistent enrollment history and actual missing/replaced source";assertions+=LumaHostedEnrollmentFixture.Run(workspace,identity,authoritySign,publisherSign,timeSign,intent,snapshot,content);
            Array.Clear(content,0,content.Length);return assertions;
        }catch(Exception error) {throw new Exception("Read fixture stage "+stage+": "+error.Message,error);}finally {
            string resolved=Path.GetFullPath(root);if(Path.GetDirectoryName(resolved)!=parent || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(resolved),"\\Awindows-read-fixtures-[0-9a-f]{32}\\z")) throw new Exception("Refuse cleanup outside the exact disposable read fixture.");Directory.Delete(resolved,true);
        }
    }
}
