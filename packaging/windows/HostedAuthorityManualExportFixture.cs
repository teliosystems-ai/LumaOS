using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Luma.Windows.Hosted;

// Real local NTFS and complete multipart DATA transfer mechanisms only. The
// fixtures do not replace a real current Admin/UTC/BitLocker/service ceremony.
public static class LumaHostedManualExportFixture
{
    private static int assertions;private static readonly Assembly library=typeof(EnrolledReadIntent).Assembly;
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateHardLink(string link,string existing,IntPtr attributes);
    private static string H(char value) {return new string(value,64);}
    private static string Hash(byte[] bytes) {using(SHA256 hash=SHA256.Create()) return Wire.Hex(hash.ComputeHash(bytes));}
    private static void Require(bool value) {if(!value) throw new Exception("Manual save mechanism assertion failed.");assertions++;}
    private static Type Kind(string name) {return library.GetType("Luma.Windows.Hosted."+name,true);}
    private static object Unwrap(Func<object> action) {try {return action();}catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}}
    private static object New(string kind,params object[] args) {return Unwrap(delegate {return Activator.CreateInstance(Kind(kind),BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public,null,args,CultureInfo.InvariantCulture);});}
    private static object Call(object target,string name,params object[] args) {return Unwrap(delegate {return target.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public).Invoke(target,args);});}
    private static object Static(string kind,string name,params object[] args) {return Unwrap(delegate {return Kind(kind).GetMethod(name,BindingFlags.Static|BindingFlags.NonPublic|BindingFlags.Public).Invoke(null,args);});}
    private static void Refuse(Action action) {try {action();}catch(SecurityException) {assertions++;return;}catch(IOException) {assertions++;return;}catch(Win32Exception) {assertions++;return;}catch(InvalidDataException) {assertions++;return;}throw new Exception("Manual save accepted a forbidden transition.");}
    private static void Own(string path,string owner) {FileSecurity acl=new FileSecurity();acl.SetSecurityDescriptorSddlForm("O:"+owner+"G:"+owner+"D:P(A;;FA;;;"+owner+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);File.SetAccessControl(path,acl);}
    private static object Read(string root,string owner,byte[] bytes,bool complete) {
        string leaf="source-"+Guid.NewGuid().ToString("N")+".bin",path=Path.Combine(root,leaf);File.WriteAllBytes(path,bytes);Own(path,owner);
        object input=New("HostedReadInputs",new string[]{"read-enrolled-file",H('1'),root,leaf,bytes.Length.ToString(CultureInfo.InvariantCulture),Hash(bytes)},false);bool returned=false;
        try {
            EnrolledReadIntent intent=(EnrolledReadIntent)Kind("HostedReadInputs").GetField("Intent",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(input);
            Refuse(delegate {Static("HostedManualSnapshot","FromCompleted",input);});
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate|TokenAccessLevels.Impersonate))
            using(IDisposable source=(IDisposable)New("EnrolledReadSource",intent,identity.AccessToken,(Action)delegate {})) {
                byte[] objectIdentity=(byte[])Call(source,"Snapshot"),actual=(byte[])Call(source,"CaptureVerified"),exact;
                try {
                    Require(Wire.Equal(actual,bytes));using(Wire.Writer review=new Wire.Writer("luma-windows-hosted-read-review-v1")) {review.Blob(intent.Encode(),2048);review.Blob(objectIdentity,4096);exact=review.Bytes();}
                    string reviewed=Wire.Hash(exact);Call(input,"Reviewed",exact,reviewed);object delivery=New("EnrolledReadDelivery",intent,reviewed,Wire.Hash(objectIdentity));Call(delivery,"Begin",Wire.Hash(intent.Encode()),Wire.Hash(objectIdentity));
                    for(int offset=0;offset<actual.Length;offset+=32768) {byte[] part=(byte[])Call(delivery,"Chunk",actual,offset),ack=null;try {ack=(byte[])Call(input,"Part",part);Call(delivery,"Acknowledge",ack,actual);}finally {Array.Clear(part,0,part.Length);if(ack!=null) Array.Clear(ack,0,ack.Length);}}
                    Refuse(delegate {Static("HostedManualSnapshot","FromCompleted",input);});
                    if(complete) {byte[] receipt=(byte[])Call(delivery,"Complete");try {Call(input,"Completed",receipt);}finally {Array.Clear(receipt,0,receipt.Length);}}
                }finally {Array.Clear(actual,0,actual.Length);}
            }
            returned=true;return input;
        }finally {if(!returned) ((IDisposable)input).Dispose();}
    }
    private static object Snapshot(string root,string owner,byte[] bytes) {
        using(IDisposable input=(IDisposable)Read(root,owner,bytes,true)) {
            object snapshot=Static("HostedManualSnapshot","FromCompleted",input);Refuse(delegate {Static("HostedManualSnapshot","FromCompleted",input);});Refuse(delegate {Call(input,"TakeCompletedForInference");});return snapshot;
        }
    }
    private static EnrolledReadIntent Intent(object snapshot) {return (EnrolledReadIntent)Kind("HostedManualSnapshot").GetField("Intent",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(snapshot);}
    private static string Review(object target,object snapshot,byte[] actor,byte[] nonce) {return (string)Call(target,"Review",Intent(snapshot),actor,nonce);}
    public static int Run(string workspace) {
        assertions=0;string owner;using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) owner=identity.User.Value;
        string parent=Path.Combine(Path.GetFullPath(workspace),".luma"),root=Path.Combine(parent,"windows-manual-save-fixtures-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(parent);
        Require(new DriveInfo(Path.GetPathRoot(root)).DriveFormat=="NTFS" && (File.GetAttributes(parent)&FileAttributes.ReparsePoint)==0);
        DirectorySecurity own=new DirectorySecurity();own.SetSecurityDescriptorSddlForm("O:"+owner+"G:"+owner+"D:P(A;OICI;FA;;;"+owner+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.CreateDirectory(root,own);
        byte[] actor=new byte[]{1,2,3},nonce=new byte[32];nonce[0]=1;int checks=0;Action current=delegate {checks++;};
        byte[] content=new byte[1048576];for(int index=0;index<content.Length;index++) content[index]=unchecked((byte)(index%251));
        using(IDisposable partial=(IDisposable)Read(root,owner,new byte[]{0xff,0,0x41},false)) {Refuse(delegate {Static("HostedManualSnapshot","FromCompleted",partial);});}
        string targetPath=Path.Combine(root,"complete.bin");
        using(IDisposable snapshot=(IDisposable)Snapshot(root,owner,content))
        using(IDisposable target=(IDisposable)New("HostedManualTarget",targetPath,owner,current)) {
            string exact=Review(target,snapshot,actor,nonce);Require(!File.Exists(targetPath));
            Refuse(delegate {Call(target,"Save",snapshot,H('a'),actor,nonce);});Require(!File.Exists(targetPath));
            byte[] changed=(byte[])nonce.Clone();changed[1]=1;Refuse(delegate {Call(target,"Save",snapshot,exact,actor,changed);});
            Call(target,"Save",snapshot,exact,actor,nonce);Require(checks>100);
            Refuse(delegate {Call(target,"Save",snapshot,exact,actor,nonce);});Refuse(delegate {Call(snapshot,"Consume");});
            Refuse(delegate {File.ReadAllBytes(targetPath);});
            Refuse(delegate {Directory.Move(root,root+"-renamed");});
        }
        Require(Wire.Equal(File.ReadAllBytes(targetPath),content));RawSecurityDescriptor saved=new RawSecurityDescriptor(File.GetAccessControl(targetPath).GetSecurityDescriptorBinaryForm(),0);
        Require(saved.Owner.Value==owner && saved.DiscretionaryAcl.Count==2 && (saved.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0);
        using(IDisposable snapshot=(IDisposable)Snapshot(root,owner,new byte[]{0xff,0,0x41}))
        using(IDisposable target=(IDisposable)New("HostedManualTarget",targetPath,owner,current)) {string exact=Review(target,snapshot,actor,nonce);Refuse(delegate {Call(target,"Save",snapshot,exact,actor,nonce);});Require(Wire.Equal(File.ReadAllBytes(targetPath),content));}
        string link=Path.Combine(root,"linked.bin");if(!CreateHardLink(link,targetPath,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using(IDisposable snapshot=(IDisposable)Snapshot(root,owner,new byte[]{1}))
        using(IDisposable target=(IDisposable)New("HostedManualTarget",link,owner,current)) {string exact=Review(target,snapshot,actor,nonce);Refuse(delegate {Call(target,"Save",snapshot,exact,actor,nonce);});Require(Wire.Equal(File.ReadAllBytes(link),content));}
        bool cancelled=false;Action cancel=delegate {if(cancelled) throw new SecurityException("Fixture original purpose revoked.");};string cancelledPath=Path.Combine(root,"cancelled.bin");
        using(IDisposable snapshot=(IDisposable)Snapshot(root,owner,new byte[]{0xff,0,0x41}))
        using(IDisposable target=(IDisposable)New("HostedManualTarget",cancelledPath,owner,cancel)) {string exact=Review(target,snapshot,actor,nonce);cancelled=true;Refuse(delegate {Call(target,"Save",snapshot,exact,actor,nonce);});Require(!File.Exists(cancelledPath));}cancelled=false;
        string protectedPath=Path.Combine(root,"protection-refused.bin");
        using(IDisposable target=(IDisposable)New("HostedManualTarget",protectedPath,owner,current)) {Refuse(delegate {Call(target,"RequireAdditionalChecks",(Action)delegate {throw new SecurityException("Fixture observed suspended protection.");});});Refuse(delegate {Call(target,"Check");});Require(!File.Exists(protectedPath));}
        foreach(string bad in new string[]{Path.Combine(root,"..","escape.bin"),Path.Combine(root,"CON"),Path.Combine(root,"file.bin:stream"),Path.Combine(root,"trailing."),Path.Combine(root,"tilde~1.bin")}) Refuse(delegate {using(IDisposable ignored=(IDisposable)New("HostedManualTarget",bad,owner,current)) {}});
        using(IDisposable snapshot=(IDisposable)Snapshot(root,owner,new byte[]{0xff,0,0x41})) {byte[] bytes=(byte[])Call(snapshot,"Consume");Require(Wire.Equal(bytes,new byte[]{0xff,0,0x41}));Array.Clear(bytes,0,bytes.Length);Refuse(delegate {Call(snapshot,"Consume");});}
        return assertions;
    }
}
