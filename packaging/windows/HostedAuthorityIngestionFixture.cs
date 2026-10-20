using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Luma.Windows.Hosted;

// Actual tiny owner-only NTFS/source/receipt mechanisms and closed software
// handoff contracts. This is NOT an installed authenticated service, TPM,
// protected UTC, guest confinement or model execution qualification.
public static class LumaHostedIngestionFixture
{
    private static int assertions;private static readonly Assembly library=typeof(EnrolledReadIntent).Assembly;
    private static string H(char value) {return new string(value,64);}
    private static void Require(bool value) {if(!value) throw new Exception("Scoped ingestion mechanism assertion failed.");assertions++;}
    private static Type Kind(string name) {return library.GetType("Luma.Windows.Hosted."+name,true);}
    private static object Unwrap(Func<object> action) {
        try {return action();}catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}
    }
    private static object New(string name,params object[] arguments) {return Unwrap(delegate {return Activator.CreateInstance(Kind(name),BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,arguments,CultureInfo.InvariantCulture);});}
    private static object Call(object target,string name,params object[] arguments) {return Unwrap(delegate {return target.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic).Invoke(target,arguments);});}
    private static object Static(string kind,string name,params object[] arguments) {return Unwrap(delegate {return Kind(kind).GetMethod(name,BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).Invoke(null,arguments);});}
    private static void Refuse(Action action) {
        try {action();}catch(SecurityException) {assertions++;return;}catch(InvalidDataException) {assertions++;return;}
        catch(EncoderFallbackException) {assertions++;return;}catch(DecoderFallbackException) {assertions++;return;}
        throw new Exception("Scoped ingestion accepted a forbidden transition.");
    }
    private static byte[] Hash(byte[] value) {using(SHA256 hash=SHA256.Create()) return hash.ComputeHash(value);}
    private static string[] ReadArguments(string root,string leaf,byte[] bytes) {return new string[]{"read-enrolled-file",H('1'),root,leaf,bytes.Length.ToString(CultureInfo.InvariantCulture),Wire.Hex(Hash(bytes))};}
    private static string[] IngestionArguments(string root,string leaf,byte[] bytes) {return new string[]{"infer-enrolled-file",H('6'),H('1'),root,leaf,bytes.Length.ToString(CultureInfo.InvariantCulture),Wire.Hex(Hash(bytes)),H('7'),H('8'),"128"};}
    private static object CompletedRead(string root,byte[] bytes,string owner) {
        string leaf="source-"+Guid.NewGuid().ToString("N")+".txt",path=Path.Combine(root,leaf);File.WriteAllBytes(path,bytes);
        FileSecurity acl=new FileSecurity();acl.SetSecurityDescriptorSddlForm("O:"+owner+"G:"+owner+"D:P(A;;FA;;;"+owner+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);File.SetAccessControl(path,acl);
        string[] arguments=ReadArguments(root,leaf,bytes);object input=New("HostedReadInputs",arguments,false);bool returned=false;
        try {
            EnrolledReadIntent intent=(EnrolledReadIntent)Kind("HostedReadInputs").GetField("Intent",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(input);
            Refuse(delegate {Static("HostedIngestionSnapshot","FromCompleted",input);});
            int checks=0;Action current=delegate {checks++;};
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate|TokenAccessLevels.Impersonate))
            using(IDisposable source=(IDisposable)New("EnrolledReadSource",intent,identity.AccessToken,current)) {
                byte[] snapshot=(byte[])Call(source,"Snapshot"),actual=(byte[])Call(source,"CaptureVerified"),exact;
                try {
                    Require(Wire.Equal(actual,bytes) && checks>10);
                    using(Wire.Writer review=new Wire.Writer("luma-windows-hosted-read-review-v1")) {review.Blob(intent.Encode(),2048);review.Blob(snapshot,4096);exact=review.Bytes();}
                    string reviewed=Wire.Hash(exact);Call(input,"Reviewed",exact,reviewed);
                    object delivery=New("EnrolledReadDelivery",intent,reviewed,Wire.Hash(snapshot));Call(delivery,"Begin",Wire.Hash(intent.Encode()),Wire.Hash(snapshot));
                    Refuse(delegate {Static("HostedIngestionSnapshot","FromCompleted",input);});
                    byte[] chunk=(byte[])Call(delivery,"Chunk",actual,0),ack=null,completion=null;
                    try {
                        ack=(byte[])Call(input,"Part",chunk);Call(delivery,"Acknowledge",ack,actual);
                        Refuse(delegate {Static("HostedIngestionSnapshot","FromCompleted",input);});
                        completion=(byte[])Call(delivery,"Complete");Call(input,"Completed",completion);Call(source,"Check");
                    }finally {Array.Clear(chunk,0,chunk.Length);if(ack!=null) Array.Clear(ack,0,ack.Length);if(completion!=null) Array.Clear(completion,0,completion.Length);}
                }finally {Array.Clear(actual,0,actual.Length);}
            }
            returned=true;return input;
        }finally {if(!returned) ((IDisposable)input).Dispose();}
    }
    public static int Run(string workspace) {
        assertions=0;string owner;using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) owner=identity.User.Value;
        string parent=Path.Combine(Path.GetFullPath(workspace),".luma"),root=Path.Combine(parent,"windows-ingestion-fixtures-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(parent);Require(new DriveInfo(Path.GetPathRoot(root)).DriveFormat=="NTFS" && (File.GetAttributes(parent)&FileAttributes.ReparsePoint)==0);
        DirectorySecurity directory=new DirectorySecurity();directory.SetSecurityDescriptorSddlForm("O:"+owner+"G:"+owner+"D:P(A;OICI;FA;;;"+owner+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.CreateDirectory(root,directory);
        try {
            byte[] text=new UTF8Encoding(false,true).GetBytes("Exact already-delivered source.\r\nCaf\u00e9 / \u6a21\u578b / \ud83d\ude80; model text is data, not authority.");
            object input=CompletedRead(root,text,owner);object snapshot=null;
            try {
                byte[] held=(byte[])Kind("HostedReadInputs").GetField("content",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(input);
                snapshot=Static("HostedIngestionSnapshot","FromCompleted",input);
                Require(Kind("HostedReadInputs").GetField("content",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(input)==null);
                Refuse(delegate {Static("HostedIngestionSnapshot","FromCompleted",input);});
                GuestInferenceRequest request=(GuestInferenceRequest)Call(snapshot,"CreateRequest",H('7'),H('8'),(uint)128);
                Require(request.PromptSha256==Wire.Hex(Hash(text)) && request.PromptBytes==text.Length && request.MaximumTokens==128);
                Require(request.RuntimeManifestSha256==H('7') && request.ProfileSha256==H('8'));
                Require(Wire.Equal(GuestInferenceRequest.Decode(request.Bytes).Bytes,request.Bytes));
                bool cleared=true;foreach(byte value in held) if(value!=0) cleared=false;Require(cleared);
                Refuse(delegate {Call(snapshot,"CreateRequest",H('7'),H('8'),(uint)128);});
            }finally {if(snapshot!=null) ((IDisposable)snapshot).Dispose();((IDisposable)input).Dispose();}
            input=CompletedRead(root,text,owner);
            try {
                snapshot=Static("HostedIngestionSnapshot","FromCompleted",input);((IDisposable)snapshot).Dispose();
                Refuse(delegate {Call(snapshot,"CreateRequest",H('7'),H('8'),(uint)128);});
            }finally {((IDisposable)input).Dispose();}
            foreach(byte[] bad in new byte[][] {new byte[]{0xff,0x41},new byte[]{0xc0,0xaf},new byte[]{0x41,0,0x42},new byte[4097]}) {
                input=CompletedRead(root,bad,owner);try {Refuse(delegate {Static("HostedIngestionSnapshot","FromCompleted",input);});}finally {((IDisposable)input).Dispose();}
            }
            byte[] limit=new UTF8Encoding(false,true).GetBytes(new string('\u00e9',2048));input=CompletedRead(root,limit,owner);
            try {snapshot=Static("HostedIngestionSnapshot","FromCompleted",input);try {GuestInferenceRequest request=(GuestInferenceRequest)Call(snapshot,"CreateRequest",H('7'),H('8'),(uint)512);Require(request.PromptBytes==4096 && request.PromptSha256==Wire.Hex(Hash(limit)));}finally {((IDisposable)snapshot).Dispose();}}
            finally {((IDisposable)input).Dispose();}
            input=CompletedRead(root,text,owner);
            try {Kind("HostedReadInputs").GetField("cancelled",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(input,1);bool refused=false;try {Static("HostedIngestionSnapshot","FromCompleted",input);}catch(OperationCanceledException) {refused=true;}Require(refused);}
            finally {((IDisposable)input).Dispose();}
            string[] good=IngestionArguments(root,"not-opened-by-constructor.txt",text);
            using(IDisposable selection=(IDisposable)New("HostedIngestionInputs",good,false)) {Call(selection,"Check");assertions++;}
            foreach(string maximum in new string[]{"0","513","0128","1.0","-1","4294967296"}) {string[] bad=(string[])good.Clone();bad[9]=maximum;Refuse(delegate {using(IDisposable selection=(IDisposable)New("HostedIngestionInputs",bad,false)) {}});}
            foreach(int field in new int[]{1,2,6,7,8}) {string[] bad=(string[])good.Clone();bad[field]="not-a-digest";Refuse(delegate {using(IDisposable selection=(IDisposable)New("HostedIngestionInputs",bad,false)) {}});}
            string[] oversized=(string[])good.Clone();oversized[5]="4097";Refuse(delegate {using(IDisposable selection=(IDisposable)New("HostedIngestionInputs",oversized,false)) {}});
            using(IDisposable selection=(IDisposable)New("HostedIngestionInputs",good,false)) {Kind("HostedIngestionInputs").GetField("cancelled",BindingFlags.Instance|BindingFlags.NonPublic).SetValue(selection,1);bool refused=false;try {Call(selection,"Check");}catch(OperationCanceledException) {refused=true;}Require(refused);}
            Static("HostedStatusShape","Require",(byte)4,H('9'),(uint)1234,(ulong)5678);assertions++;
            Static("HostedStatusShape","Require",(byte)0,"",(uint)0,(ulong)0);assertions++;
            Static("HostedStatusShape","Require",(byte)5,H('9'),(uint)0,(ulong)0);assertions++;
            Refuse(delegate {Static("HostedStatusShape","Require",(byte)6,H('9'),(uint)0,(ulong)0);});
            Refuse(delegate {Static("HostedStatusShape","Require",(byte)4,"",(uint)0,(ulong)0);});
            Refuse(delegate {Static("HostedStatusShape","Require",(byte)0,H('9'),(uint)0,(ulong)0);});
            Refuse(delegate {Static("HostedStatusShape","Require",(byte)4,H('9'),(uint)1234,(ulong)0);});
            return assertions;
        }finally {if(Directory.Exists(root)) Directory.Delete(root,true);}
    }
}
