[CmdletBinding()]
param([Parameter(Mandatory)][string] $BuildRoot,[string] $InferenceCasesPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$build=& (Join-Path $PSScriptRoot 'build-hosted-authority.ps1') -BuildRoot $BuildRoot -LibraryOnly
foreach ($name in @('Luma.PlatformSignature.dll','Luma.PlatformCustody.dll','Luma.PackageInspector.dll','Luma.HostedAuthority.Library.dll')) {
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build.work_directory $name))
}
$priorTemp=$env:TEMP;$priorTmp=$env:TMP
$keys=@();$script:HostedAssertions=0
function Assert-Hosted([bool] $Condition,[string] $Message) {if (-not $Condition) {throw $Message};$script:HostedAssertions++}
function Assert-HostedThrows([scriptblock] $Action,[string] $Message) {
    $refused=$false
    try {$null=& $Action} catch {
        $leaf=$_.Exception.GetBaseException()
        if ($_.FullyQualifiedErrorId -match 'PropertyNotFound|MethodNotFound|TypeNotFound|CommandNotFound|UnexpectedToken' -or
            $leaf -is [NullReferenceException] -or $leaf -is [IndexOutOfRangeException] -or $leaf -is [InvalidCastException] -or
            $leaf -is [OutOfMemoryException] -or $leaf -is [AccessViolationException]) {throw ('Implementation error is not an expected refusal: '+$_)}
        $refused=$true
    }
    Assert-Hosted $refused $Message
}
try {
    $env:TEMP=$build.work_directory;$env:TMP=$build.work_directory
    [string[]]$componentNames=@($build.components | ForEach-Object {$_.name})
    [string[]]$ordinalNames=$componentNames.Clone();[Array]::Sort($ordinalNames,[StringComparer]::Ordinal)
    Assert-Hosted (($componentNames -join '|') -ceq ($ordinalNames -join '|')) 'Executable/DLL bundle canonical order is not ordinal and installer-compatible.'
    $canonical="luma-windows-hosted-runtime-bundle-v1`n"
    foreach ($component in $build.components) {$canonical+=$component.name+"`t"+$component.bytes.ToString([Globalization.CultureInfo]::InvariantCulture)+"`t"+$component.sha256+"`n"}
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Hash([Text.Encoding]::UTF8.GetBytes($canonical)) -ceq $build.bundle_sha256) 'Canonical component bundle digest differs from actual emitted build manifest.'
    Assert-Hosted ([IO.File]::ReadAllText($build.bundle_manifest,[Text.Encoding]::UTF8) -ceq $canonical) 'Emitted bundle manifest order/bytes differ from reviewed component table.'
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public sealed class LumaHostedEphemeralFixture : IDisposable {
    private IntPtr algorithm,key;
    [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] private static extern int BCryptOpenAlgorithmProvider(out IntPtr algorithm,string name,string provider,uint flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptGenerateKeyPair(IntPtr algorithm,out IntPtr key,uint bits,uint flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptFinalizeKeyPair(IntPtr key,uint flags);
    [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] private static extern int BCryptExportKey(IntPtr key,IntPtr export,string kind,byte[] bytes,uint maximum,out uint written,uint flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptSignHash(IntPtr key,IntPtr padding,byte[] hash,uint bytes,byte[] signature,uint maximum,out uint written,uint flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptDestroyKey(IntPtr key);
    [DllImport("bcrypt.dll")] private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm,uint flags);
    private static void Check(int value) {if(value!=0) throw new CryptographicException("Actual ephemeral fixture failed: "+((uint)value).ToString("x8"));}
    public LumaHostedEphemeralFixture() {
        try {Check(BCryptOpenAlgorithmProvider(out algorithm,"ECDSA_P256","Microsoft Primitive Provider",0));
            Check(BCryptGenerateKeyPair(algorithm,out key,256,0));Check(BCryptFinalizeKeyPair(key,0));}
        catch {Dispose();throw;}
    }
    public byte[] PublicBlob() {byte[] value=new byte[72];uint count;Check(BCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",value,72,out count,0));if(count!=72) throw new CryptographicException("Unexpected public fixture size.");return value;}
    public byte[] Sign(byte[] input) {byte[] digest;using(SHA256 hash=SHA256.Create()) digest=hash.ComputeHash(input);byte[] value=new byte[64];uint count;
        Check(BCryptSignHash(key,IntPtr.Zero,digest,32,value,64,out count,0));if(count!=64) throw new CryptographicException("Unexpected signature size.");return value;}
    public void Dispose() {if(key!=IntPtr.Zero){BCryptDestroyKey(key);key=IntPtr.Zero;}if(algorithm!=IntPtr.Zero){BCryptCloseAlgorithmProvider(algorithm,0);algorithm=IntPtr.Zero;}}
}
'@
    for ($index=0;$index -lt 8;$index++) {$keys+=New-Object LumaHostedEphemeralFixture}
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),'System.dll','System.Core.dll') -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Luma.Windows.Hosted;
public static class LumaHostedLifecycleFixture {
    private static object NewServiceWorker(Action serve,Action<int> stopped,Action<string> fatal) {
        Type type=typeof(RuntimeBundle).Assembly.GetType("Luma.Windows.Hosted.HostedServiceWorker",true);
        return Activator.CreateInstance(type,BindingFlags.NonPublic|BindingFlags.Instance,null,new object[]{serve,stopped,fatal},null);
    }
    private static object ServiceInvoke(object worker,string method,params object[] arguments) {
        MethodInfo operation=worker.GetType().GetMethod(method,BindingFlags.NonPublic|BindingFlags.Instance);if(operation==null) throw new MissingMethodException(worker.GetType().FullName,method);
        try {return operation.Invoke(worker,arguments);}catch(TargetInvocationException error) {if(error.InnerException==null) throw;System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
    private static bool ServiceStopping(object worker) {return (bool)worker.GetType().GetProperty("Stopping",BindingFlags.NonPublic|BindingFlags.Instance).GetValue(worker,null);}
    private sealed class FixtureEndpoint : IDisposable {
        private readonly Action close;internal FixtureEndpoint(Action close) {this.close=close;}public void Dispose() {close();}
    }
    private static void RequireWait(WaitHandle signal) {if(!signal.WaitOne(5000)) throw new Exception("Actual lifecycle worker failed its bounded software fixture.");}
    public static int RunServiceLifetime() {
        int assertions=0;
        Action[] exits={delegate {},delegate {throw new System.ComponentModel.Win32Exception(5);},delegate {throw new SecurityException("fixture");},delegate {throw new IOException("fixture");},delegate {throw new InvalidOperationException("fixture");}};
        foreach(Action body in exits) {
            using(ManualResetEvent reported=new ManualResetEvent(false)) {
                object worker=null;int reports=0,fatals=0,code=0;bool selfDrained=false;
                worker=NewServiceWorker(body,delegate(int value) {code=value;Interlocked.Increment(ref reports);selfDrained=(bool)ServiceInvoke(worker,"Stop");reported.Set();},delegate(string reason) {Interlocked.Increment(ref fatals);reported.Set();});
                ServiceInvoke(worker,"Start");RequireWait(reported);if(!(bool)ServiceInvoke(worker,"Stop") || reports!=1 || fatals!=0 || code!=1 || !selfDrained || !ServiceStopping(worker)) throw new Exception("Unexpected worker exit failed to report exactly one failure/stop without self-join.");assertions++;
                try {ServiceInvoke(worker,"Start");throw new Exception("Stopped worker restarted without a new SCM lifetime.");}catch(InvalidOperationException) {}assertions++;
            }
        }
        using(ManualResetEvent ready=new ManualResetEvent(false)) using(ManualResetEvent release=new ManualResetEvent(false)) {
            object worker=null;int reports=0,fatals=0,closes=0;FixtureEndpoint endpoint=new FixtureEndpoint(delegate {Interlocked.Increment(ref closes);release.Set();});
            worker=NewServiceWorker(delegate {ServiceInvoke(worker,"Publish",endpoint);ready.Set();try {RequireWait(release);}finally {ServiceInvoke(worker,"Clear",endpoint);}},delegate(int value) {Interlocked.Increment(ref reports);},delegate(string reason) {Interlocked.Increment(ref fatals);});
            ServiceInvoke(worker,"Start");RequireWait(ready);if(!(bool)ServiceInvoke(worker,"Stop") || closes!=1 || reports!=0 || fatals!=0) throw new Exception("Explicit stop did not close and join its actual endpoint worker.");assertions++;
            try {ServiceInvoke(worker,"Publish",endpoint);throw new Exception("Endpoint published after stop could orphan a new listener.");}catch(IOException) {}assertions++;
        }
        using(ManualResetEvent ready=new ManualResetEvent(false)) using(ManualResetEvent release=new ManualResetEvent(false)) using(ManualResetEvent stopped=new ManualResetEvent(false)) {
            object worker=null;int reports=0,fatals=0;bool drained=false,publishRefused=false;
            worker=NewServiceWorker(delegate {ready.Set();RequireWait(release);try {ServiceInvoke(worker,"Publish",new FixtureEndpoint(delegate {}));}catch(IOException) {publishRefused=true;}},delegate(int value) {Interlocked.Increment(ref reports);},delegate(string reason) {Interlocked.Increment(ref fatals);});
            ServiceInvoke(worker,"Start");RequireWait(ready);Thread stopThread=new Thread(delegate() {drained=(bool)ServiceInvoke(worker,"Stop");stopped.Set();});stopThread.Start();
            try {System.Diagnostics.Stopwatch age=System.Diagnostics.Stopwatch.StartNew();while(!ServiceStopping(worker)) {if(age.Elapsed.TotalSeconds>=5) throw new Exception("Stop publication gate did not close.");Thread.Sleep(1);}release.Set();RequireWait(stopped);if(!drained || !publishRefused || reports!=0 || fatals!=0) throw new Exception("Stop/publication race left a listener or false failure.");assertions++;}
            finally {release.Set();if(!stopThread.Join(5000)) throw new Exception("Fixture stop controller did not exit.");ServiceInvoke(worker,"Stop");}
        }
        using(ManualResetEvent ready=new ManualResetEvent(false)) using(ManualResetEvent release=new ManualResetEvent(false)) using(ManualResetEvent exited=new ManualResetEvent(false)) {
            object worker=null;int reports=0,fatals=0;FixtureEndpoint endpoint=new FixtureEndpoint(delegate {throw new IOException("fixture close failed");});
            worker=NewServiceWorker(delegate {ServiceInvoke(worker,"Publish",endpoint);ready.Set();try {release.WaitOne();}finally {ServiceInvoke(worker,"Clear",endpoint);exited.Set();}},delegate(int value) {Interlocked.Increment(ref reports);},delegate(string reason) {Interlocked.Increment(ref fatals);});
            ServiceInvoke(worker,"Start");RequireWait(ready);try {if((bool)ServiceInvoke(worker,"Stop")) throw new Exception("Endpoint disposal failure was reported drained.");assertions++;}finally {release.Set();}
            RequireWait(exited);if(!(bool)ServiceInvoke(worker,"Stop") || reports!=0 || fatals!=0) throw new Exception("Explicit stop cleanup forged a worker failure report or failed to exit.");assertions++;
        }
        using(ManualResetEvent ready=new ManualResetEvent(false)) using(ManualResetEvent release=new ManualResetEvent(false)) {
            int reports=0,fatals=0;object worker=NewServiceWorker(delegate {ready.Set();release.WaitOne();},delegate(int value) {Interlocked.Increment(ref reports);},delegate(string reason) {Interlocked.Increment(ref fatals);});
            ServiceInvoke(worker,"Start");RequireWait(ready);try {if((bool)ServiceInvoke(worker,"Stop")) throw new Exception("Undrained worker was reported stopped before its actual exit.");assertions++;}finally {release.Set();}
            if(!(bool)ServiceInvoke(worker,"Stop") || reports!=0 || fatals!=0) throw new Exception("Fixture blocked worker did not drain after explicit release.");assertions++;
        }
        using(ManualResetEvent fatal=new ManualResetEvent(false)) {
            int reports=0,fatals=0;object worker=NewServiceWorker(delegate {throw new SecurityException("fixture");},delegate(int value) {Interlocked.Increment(ref reports);throw new IOException("fixture SCM report failed");},delegate(string reason) {Interlocked.Increment(ref fatals);fatal.Set();});
            ServiceInvoke(worker,"Start");RequireWait(fatal);if(!(bool)ServiceInvoke(worker,"Stop") || reports!=1 || fatals!=1) throw new Exception("SCM reporting failure did not select fail-stop termination.");assertions++;
        }
        using(ManualResetEvent fatal=new ManualResetEvent(false)) {
            int reports=0,fatals=0;object worker=NewServiceWorker(delegate {throw new OutOfMemoryException("synthetic fixture; no allocation pressure");},delegate(int value) {Interlocked.Increment(ref reports);},delegate(string reason) {Interlocked.Increment(ref fatals);fatal.Set();});
            ServiceInvoke(worker,"Start");RequireWait(fatal);if(!(bool)ServiceInvoke(worker,"Stop") || reports!=0 || fatals!=1) throw new Exception("Catastrophic worker exit attempted ordinary service continuation.");assertions++;
        }
        return assertions;
    }
    private static object InstalledInvoke(object target,string method,params object[] arguments) {
        Type type=typeof(RuntimeBundle).Assembly.GetType("Luma.Windows.Hosted.InstalledInputLease",true);MethodInfo operation=type.GetMethod(method,BindingFlags.NonPublic|(target==null?BindingFlags.Static:BindingFlags.Instance));
        if(operation==null) throw new MissingMethodException(type.FullName,method);try {return operation.Invoke(target,arguments);}catch(TargetInvocationException error) {if(error.InnerException==null) throw;System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
    private static void KernelRefuse(Action action) {try {action();}catch(IOException) {return;}catch(UnauthorizedAccessException) {return;}throw new Exception("Kernel permitted mutation of an actually held immutable file/directory.");}
    public static int RunInstalledLease(string workspace) {
        workspace=Path.GetFullPath(workspace);string parent=Path.Combine(workspace,".luma"),root=Path.Combine(parent,"windows-runtime-fixtures-"+Guid.NewGuid().ToString("N"));int assertions=0;
        if(new DriveInfo(Path.GetPathRoot(root)).DriveFormat!="NTFS") throw new Exception("Actual tiny NTFS mechanism fixture is required, not an exFAT success substitute.");
        Directory.CreateDirectory(parent);if((File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0) throw new Exception("Fixture parent must not be linked.");string sid;using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) sid=identity.User.Value;
        DirectorySecurity security=new DirectorySecurity();security.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.CreateDirectory(root,security);
        try {
            string directory=Path.Combine(root,"parent"),grand=Path.Combine(directory,"child"),file=Path.Combine(grand,"source.bin");Directory.CreateDirectory(grand);File.WriteAllBytes(file,new byte[64]);
            using(IDisposable lease=(IDisposable)InstalledInvoke(null,"Acquire",file)) {
                InstalledInvoke(lease,"Check");assertions++;Directory.CreateDirectory(Path.Combine(directory,"new-sibling"));Directory.CreateDirectory(Path.Combine(root,"another-child"));File.WriteAllBytes(Path.Combine(root,"unrelated.bin"),new byte[1]);
                InstalledInvoke(lease,"Check");assertions++;KernelRefuse(delegate {File.WriteAllBytes(file,new byte[65]);});assertions++;KernelRefuse(delegate {File.Move(file,file+".renamed");});assertions++;
                KernelRefuse(delegate {Directory.Move(directory,directory+"-renamed");});assertions++;InstalledInvoke(lease,"Check");assertions++;
            }
            FileAttributes before=File.GetAttributes(file);bool changed=false;
            try {using(IDisposable lease=(IDisposable)InstalledInvoke(null,"Acquire",file)) {
                try {File.SetAttributes(file,before|FileAttributes.Hidden);changed=true;}catch(IOException) {}catch(UnauthorizedAccessException) {}
                if(changed) Refuse(delegate {InstalledInvoke(lease,"Check");});else InstalledInvoke(lease,"Check");assertions++;
            }}finally {if(changed) File.SetAttributes(file,before);}
            DirectorySecurity original=Directory.GetAccessControl(directory,AccessControlSections.Owner|AccessControlSections.Access);
            try {using(IDisposable lease=(IDisposable)InstalledInvoke(null,"Acquire",file)) {
                DirectorySecurity altered=new DirectorySecurity();altered.SetSecurityDescriptorSddlForm("O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;0x1200a9;;;BU)",AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);Directory.SetAccessControl(directory,altered);
                Refuse(delegate {InstalledInvoke(lease,"Check");});assertions++;
            }}finally {Directory.SetAccessControl(directory,original);}
            string service="S-1-5-80-1-2-3-4-5";FileSecurity filePolicy=new FileSecurity();filePolicy.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)");RuntimePermissionPolicy.Validate(filePolicy.GetSecurityDescriptorBinaryForm(),false,false,service);assertions++;
            filePolicy.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)");Refuse(delegate {RuntimePermissionPolicy.Validate(filePolicy.GetSecurityDescriptorBinaryForm(),false,false,service);});assertions++;
            filePolicy.SetSecurityDescriptorSddlForm("O:"+sid+"G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)");Refuse(delegate {RuntimePermissionPolicy.Validate(filePolicy.GetSecurityDescriptorBinaryForm(),false,false,service);});assertions++;
            return assertions;
        }finally {
            string resolved=Path.GetFullPath(root);if(Path.GetDirectoryName(resolved)!=parent || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(resolved),"\\Awindows-runtime-fixtures-[0-9a-f]{32}\\z")) throw new Exception("Refuse cleanup outside the exact newly created fixture directory.");
            Directory.Delete(resolved,true);
        }
    }
    public static RuntimeBundle SoftwareBaseline(AuthorityIdentity identity) {
        return new RuntimeBundle(new RuntimeComponent[]{new RuntimeComponent("Luma.HostedAuthority.exe",64,identity.ServiceSha256),new RuntimeComponent("Luma.PackageInspector.dll",64,H('1')),new RuntimeComponent("Luma.PlatformCustody.dll",64,H('2')),new RuntimeComponent("Luma.PlatformSignature.dll",64,H('3'))});
    }
    private sealed class Transition {
        internal JournalKind Kind;internal DeploymentEvent Event;
        internal Transition(JournalKind kind,DeploymentEvent value) {Kind=kind;Event=value;}
    }
    private static readonly string Zero=new string('0',64);
    private static string H(char value) {return new string(value,64);}
    private static DeploymentEvent Event(byte purpose,char release,ulong sequence,char generation,char leaf,uint pid,ulong created,byte outcome,char observation) {
        return new DeploymentEvent(purpose,H(release),sequence,H(generation),17,"ticket-package-"+new string(leaf,32)+".tar",pid,created,outcome,H(observation));
    }
    private static Transition T(JournalKind kind,DeploymentEvent value) {return new Transition(kind,value);}
    private static JournalHistory History(AuthorityIdentity identity,Func<byte[],byte[]> sign,params Transition[] transitions) {
        List<byte[]> records=new List<byte[]>();string head=Zero,previous=Zero;ulong sequence=1;
        JournalEntry genesis=JournalEntry.Prepare(identity,sequence,JournalKind.Commission,head,previous,identity.FirstAdminSid,identity.Encode());
        genesis=genesis.Signed(identity,sign(genesis.SigningInput));records.Add(genesis.Bytes);head=genesis.NextHead;previous=genesis.RecordSha256;
        foreach(Transition item in transitions) {
            JournalEntry record=JournalEntry.Prepare(identity,++sequence,item.Kind,head,previous,identity.FirstAdminSid,item.Event.Encode());
            record=record.Signed(identity,sign(record.SigningInput));records.Add(record.Bytes);head=record.NextHead;previous=record.RecordSha256;
        }
        return JournalHistory.Replay(identity,records.ToArray());
    }
    private static void Require(bool condition) {if(!condition) throw new Exception("Actual signed deployment lifecycle assertion failed.");}
    private static void Refuse(Action action) {
        try {action();} catch(SecurityException) {return;} catch(InvalidDataException) {return;} catch(EndOfStreamException) {return;}
        throw new Exception("Actual signed deployment lifecycle accepted a forbidden transition.");
    }
    private static JournalHistory Add(AuthorityIdentity identity,Func<byte[],byte[]> sign,JournalHistory prior,JournalKind kind,byte[] payload) {
        List<byte[]> records=new List<byte[]>();foreach(JournalEntry entry in prior.Entries) records.Add(entry.Bytes);
        JournalEntry next=JournalEntry.Prepare(identity,prior.Sequence+1,kind,prior.Head,prior.Record,identity.FirstAdminSid,payload);next=next.Signed(identity,sign(next.SigningInput));records.Add(next.Bytes);return JournalHistory.Replay(identity,records.ToArray());
    }
    private static byte[] TimeProof(AuthorityIdentity identity,TrustChange change,char nonce) {return new TimeAttestation(identity.Installation,H(nonce),Wire.Hash(change.Encode()),1000,1001).Encode();}
    private static HostedRuntimeState RuntimeState(AuthorityIdentity identity,CommissionIntent intent,JournalHistory history) {return HostedRuntimeState.Replay(identity,intent.Baseline,HostedTrustState.Replay(identity,intent,history,delegate {}),history,delegate {});}
    public static int RunRuntime(AuthorityIdentity identity,Func<byte[],byte[]> authority,Func<byte[],byte[]> publisher,Func<byte[],byte[]> time,byte[] replacementPublisher,Func<byte[],byte[]> replacementSign) {
        int assertions=0;RuntimeBundle baseline=SoftwareBaseline(identity);CommissionIntent intent=new CommissionIntent(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,identity.ReleaseKey,identity.TimeKey,identity.ServiceSha256,identity.WslSha256,"https://time.example.invalid/luma/challenge",baseline);
        JournalEntry first=JournalEntry.Prepare(identity,1,JournalKind.Commission,Zero,Zero,identity.FirstAdminSid,intent.GenesisPayload(identity));first=first.Signed(identity,authority(first.SigningInput));JournalHistory initial=JournalHistory.Replay(identity,new byte[][]{first.Bytes});
        HostedRuntimeState state=RuntimeState(identity,intent,initial);Require(state.Generation==0 && state.Current.Sha256==baseline.Sha256 && state.Pending==null && state.Slot=="");assertions++;
        RuntimeComponent[] components=baseline.Components;components[0]=new RuntimeComponent(components[0].Name,128,H('4'));RuntimeBundle nextBundle=new RuntimeBundle(components);
        RuntimeUpdate update=new RuntimeUpdate(identity.Installation,1,state.SourceSha256,1,10000,nextBundle,H('5'));byte[] publisherSignature=publisher(update.SigningInput());
        byte[] proof=new TimeAttestation(identity.Installation,H('a'),Wire.Hash(update.Encode()),1000,1001).Encode();RuntimePreparation preparation=new RuntimePreparation(update,H('a'),publisherSignature,proof,time(proof));
        JournalHistory prepared=Add(identity,authority,initial,JournalKind.RuntimePrepared,preparation.Encode());state=RuntimeState(identity,intent,prepared);
        Require(state.Pending!=null && state.Current.Sha256==baseline.Sha256 && state.Generation==0);assertions++;
        Refuse(delegate {Require(state.GuestExecutionIdentity!=null);});assertions++;
        Require(Wire.Equal(RuntimeBundle.Decode(nextBundle.Encode()).Encode(),nextBundle.Encode()) && Wire.Equal(RuntimeUpdate.Decode(update.Encode()).Encode(),update.Encode()) && Wire.Equal(RuntimePreparation.Decode(preparation.Encode()).Encode(),preparation.Encode()));assertions++;
        byte[] completionProof=new TimeAttestation(identity.Installation,H('b'),Wire.Hash(update.Encode()),1000,1001).Encode();RuntimeCompletion completion=new RuntimeCompletion(Wire.Hash(preparation.Encode()),false,publisherSignature,completionProof,time(completionProof));
        JournalHistory active=Add(identity,authority,prepared,JournalKind.RuntimeActivated,completion.Encode());state=RuntimeState(identity,intent,active);Require(state.Pending==null && state.Generation==1 && state.Current.Sha256==nextBundle.Sha256 && state.WslSha256==H('5') && state.Slot==H('a'));assertions++;
        AuthorityIdentity execution=state.GuestExecutionIdentity;
        Require(execution.WslSha256==H('5') && execution.WslSha256!=identity.WslSha256 && execution.ServiceSha256==nextBundle.ServiceSha256 &&
            execution.Installation==identity.Installation && execution.FirstAdminSid==identity.FirstAdminSid && Wire.Equal(execution.AuthorityKey,identity.AuthorityKey));assertions++;
        HostedRuntimeDependencyPolicy.RequireWsl(execution.WslSha256,H('5'));assertions++;
        Refuse(delegate {HostedRuntimeDependencyPolicy.RequireWsl(execution.WslSha256,identity.WslSha256);});assertions++;
        Refuse(delegate {HostedRuntimeDependencyPolicy.RequireWsl(execution.WslSha256,H('6'));});assertions++;
        Require(identity.WslSha256!=H('5') && identity.ServiceSha256==intent.ServiceSha256 && JournalHistory.Replay(identity,Array.ConvertAll(active.Entries,delegate(JournalEntry value) {return value.Bytes;})).Head==active.Head);assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,initial,JournalKind.RuntimeActivated,completion.Encode()));});assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimePrepared,preparation.Encode()));});assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeActivated,new RuntimeCompletion(H('1'),false,publisherSignature,completionProof,time(completionProof)).Encode()));});assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeCancelled,completion.Encode()));});assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeActivated,new RuntimeCompletion(Wire.Hash(preparation.Encode()),false,authority(update.SigningInput()),completionProof,time(completionProof)).Encode()));});assertions++;
        byte[] wrongSource=new TimeAttestation(identity.Installation,H('b'),H('8'),1000,1001).Encode();Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeActivated,new RuntimeCompletion(Wire.Hash(preparation.Encode()),false,publisherSignature,wrongSource,time(wrongSource)).Encode()));});assertions++;
        byte[] expired=new TimeAttestation(identity.Installation,H('c'),Wire.Hash(update.Encode()),20000,20001).Encode();Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeActivated,new RuntimeCompletion(Wire.Hash(preparation.Encode()),false,publisherSignature,expired,time(expired)).Encode()));});assertions++;
        RuntimeCompletion cancel=new RuntimeCompletion(Wire.Hash(preparation.Encode()),true,new byte[64],expired,time(expired));JournalHistory cancelled=Add(identity,authority,prepared,JournalKind.RuntimeCancelled,cancel.Encode());state=RuntimeState(identity,intent,cancelled);
        Require(state.Pending==null && state.Generation==1 && state.Current.Sha256==baseline.Sha256 && state.Slot=="" && state.SourceSha256==Wire.Hash(cancel.Encode()));assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,prepared,JournalKind.RuntimeCancelled,new RuntimeCompletion(Wire.Hash(preparation.Encode()),true,publisherSignature,expired,time(expired)).Encode()));});assertions++;
        RuntimeUpdate retry=new RuntimeUpdate(identity.Installation,2,state.SourceSha256,1,10000,nextBundle,H('5'));byte[] retryProof=new TimeAttestation(identity.Installation,H('d'),Wire.Hash(retry.Encode()),1000,1001).Encode();
        RuntimePreparation reused=new RuntimePreparation(retry,H('a'),publisher(retry.SigningInput()),retryProof,time(retryProof));Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,cancelled,JournalKind.RuntimePrepared,reused.Encode()));});assertions++;
        RuntimePreparation fresh=new RuntimePreparation(retry,H('b'),publisher(retry.SigningInput()),retryProof,time(retryProof));Require(RuntimeState(identity,intent,Add(identity,authority,cancelled,JournalKind.RuntimePrepared,fresh.Encode())).Pending.Slot==H('b'));assertions++;
        RuntimeUpdate stale=new RuntimeUpdate(identity.Installation,2,H('7'),1,10000,nextBundle,H('5'));byte[] staleProof=new TimeAttestation(identity.Installation,H('e'),Wire.Hash(stale.Encode()),1000,1001).Encode();Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,cancelled,JournalKind.RuntimePrepared,new RuntimePreparation(stale,H('c'),publisher(stale.SigningInput()),staleProof,time(staleProof)).Encode()));});assertions++;
        HostedRuntimeState genesis=RuntimeState(identity,intent,initial);RuntimeUpdate unchanged=new RuntimeUpdate(identity.Installation,1,genesis.SourceSha256,1,10000,baseline,identity.WslSha256);byte[] sameProof=new TimeAttestation(identity.Installation,H('f'),Wire.Hash(unchanged.Encode()),1000,1001).Encode();Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,initial,JournalKind.RuntimePrepared,new RuntimePreparation(unchanged,H('c'),publisher(unchanged.SigningInput()),sameProof,time(sameProof)).Encode()));});assertions++;
        HostedTrustState trust=HostedTrustState.Replay(identity,intent,prepared,delegate {});TrustChange revoke=new TrustChange(3,identity.Installation,1,trust.SourceSha256,1,10000,identity.ReleaseKey,identity.TimeKey,intent.TimeEndpoint);byte[] revocationProof=TimeProof(identity,revoke,'1');
        JournalHistory revoked=Add(identity,authority,prepared,JournalKind.TrustChanged,new TrustRecord(revoke,new byte[64],new byte[64],revocationProof,time(revocationProof),new byte[0],new byte[0]).Encode());
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,revoked,JournalKind.RuntimeActivated,completion.Encode()));});assertions++;
        Require(RuntimeState(identity,intent,Add(identity,authority,revoked,JournalKind.RuntimeCancelled,cancel.Encode())).Pending==null);assertions++;
        HostedTrustState revokedState=HostedTrustState.Replay(identity,intent,revoked,delegate {});TrustChange recover=new TrustChange(5,identity.Installation,2,revokedState.SourceSha256,1,10000,replacementPublisher,identity.TimeKey,intent.TimeEndpoint);byte[] recoverProof=TimeProof(identity,recover,'2');
        JournalHistory recovered=Add(identity,authority,revoked,JournalKind.TrustChanged,new TrustRecord(recover,new byte[64],replacementSign(recover.AcceptanceInput()),recoverProof,time(recoverProof),new byte[0],new byte[0]).Encode());
        RuntimeCompletion reauthorized=new RuntimeCompletion(Wire.Hash(preparation.Encode()),false,replacementSign(update.SigningInput()),completionProof,time(completionProof));
        Require(RuntimeState(identity,intent,Add(identity,authority,recovered,JournalKind.RuntimeActivated,reauthorized.Encode())).Current.Sha256==nextBundle.Sha256);assertions++;
        Refuse(delegate {RuntimeState(identity,intent,Add(identity,authority,recovered,JournalKind.RuntimeActivated,completion.Encode()));});assertions++;
        Refuse(delegate {new RuntimeBundle(new RuntimeComponent[]{components[1],components[0],components[2],components[3]});});assertions++;
        Refuse(delegate {new RuntimeComponent("Luma.HostedAuthority.exe",134217729,H('1'));});assertions++;
        Refuse(delegate {HostedRuntimeState.Replay(identity,baseline,HostedTrustState.Replay(identity,intent,active,delegate {}),active,delegate {throw new SecurityException("Actual runtime replay cancellation.");});});assertions++;
        Require(Wire.Equal(RuntimeCompletion.Decode(completion.Encode()).Encode(),completion.Encode()));assertions++;
        return assertions;
    }
    public static int RunTrust(AuthorityIdentity identity,Func<byte[],byte[]> authority,Func<byte[],byte[]> publisher,Func<byte[],byte[]> time,
        byte[] newPublisher,Func<byte[],byte[]> newPublisherSign,byte[] newTime,Func<byte[],byte[]> newTimeSign,byte[] recoveryPublisher,Func<byte[],byte[]> recoveryPublisherSign,byte[] recoveryTime,Func<byte[],byte[]> recoveryTimeSign) {
        int assertions=0;byte[] empty=new byte[0],zeros=new byte[64];Action check=delegate {};
        CommissionIntent intent=new CommissionIntent(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,identity.ReleaseKey,identity.TimeKey,identity.ServiceSha256,identity.WslSha256,"https://time.example.invalid/luma/challenge",SoftwareBaseline(identity));
        JournalEntry first=JournalEntry.Prepare(identity,1,JournalKind.Commission,Zero,Zero,identity.FirstAdminSid,intent.GenesisPayload(identity));first=first.Signed(identity,authority(first.SigningInput));
        JournalHistory initial=JournalHistory.Replay(identity,new byte[][]{first.Bytes});
        initial=Add(identity,authority,initial,JournalKind.ImportPrepared,Event(1,'1',1,'a','b',0,0,0,'0').Encode());
        HostedTrustState state=HostedTrustState.Replay(identity,intent,initial,check);Require(state.Generation==0 && !state.PublisherRevoked && !state.TimeRevoked);assertions++;
        TrustChange rotation=new TrustChange(1,identity.Installation,1,state.SourceSha256,1,10000,newPublisher,identity.TimeKey,intent.TimeEndpoint);
        byte[] oldProof=TimeProof(identity,rotation,'a');TrustRecord record=new TrustRecord(rotation,publisher(rotation.SigningInput()),newPublisherSign(rotation.AcceptanceInput()),oldProof,time(oldProof),empty,empty);
        JournalHistory rotated=Add(identity,authority,initial,JournalKind.TrustChanged,record.Encode());state=HostedTrustState.Replay(identity,intent,rotated,check);
        Require(state.Generation==1 && Wire.Equal(state.ForRelease().ReleaseKey,newPublisher));assertions++;
        Require(Wire.Equal(state.ForCleanup(H('a')).ReleaseKey,identity.ReleaseKey));assertions++;
        Require(Wire.Equal(TrustChange.Decode(rotation.Encode()).Encode(),rotation.Encode()) && Wire.Equal(TrustRecord.Decode(record.Encode()).Encode(),record.Encode()));assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,initial,JournalKind.TrustChanged,new TrustRecord(rotation,newPublisherSign(rotation.SigningInput()),newPublisherSign(rotation.AcceptanceInput()),oldProof,time(oldProof),empty,empty).Encode()),check);});assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,initial,JournalKind.TrustChanged,new TrustRecord(rotation,publisher(rotation.SigningInput()),publisher(rotation.AcceptanceInput()),oldProof,time(oldProof),empty,empty).Encode()),check);});assertions++;
        byte[] wrongTime=TimeProof(identity,rotation,'b');Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,initial,JournalKind.TrustChanged,new TrustRecord(rotation,publisher(rotation.SigningInput()),newPublisherSign(rotation.AcceptanceInput()),wrongTime,newTimeSign(wrongTime),empty,empty).Encode()),check);});assertions++;
        Refuse(delegate {state.Validate(rotation,publisher(rotation.SigningInput()),newPublisherSign(rotation.AcceptanceInput()));});assertions++;
        HostedTrustState afterPublisher=state;
        TrustChange timeChange=new TrustChange(2,identity.Installation,2,state.SourceSha256,1,10000,newPublisher,newTime,"https://time.example.invalid/luma/replacement");
        oldProof=TimeProof(identity,timeChange,'c');byte[] newProof=TimeProof(identity,timeChange,'d');byte[] timePublisherSignature=newPublisherSign(timeChange.SigningInput()),preparedOldSignature=time(oldProof);
        TrustRecord timeRecord=new TrustRecord(timeChange,timePublisherSignature,zeros,oldProof,preparedOldSignature,newProof,newTimeSign(newProof));
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,rotated,JournalKind.TrustChanged,timeRecord.Encode()),check);});assertions++;
        TrustPreparation timePreparation=new TrustPreparation(timeChange,timePublisherSignature,zeros,oldProof,preparedOldSignature);
        JournalHistory preparedTime=Add(identity,authority,rotated,JournalKind.TrustPrepared,timePreparation.Encode());HostedTrustState preparedState=HostedTrustState.Replay(identity,intent,preparedTime,check);
        Require(preparedState.Pending!=null && preparedState.Generation==1 && Wire.Equal(preparedState.CurrentIdentity.TimeKey,identity.TimeKey));assertions++;
        Refuse(delegate {preparedState.ForRelease();});assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustPrepared,timePreparation.Encode()),check);});assertions++;
        byte[] substitutedOld=TimeProof(identity,timeChange,'5');
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustChanged,new TrustRecord(timeChange,timePublisherSignature,zeros,substitutedOld,time(substitutedOld),newProof,newTimeSign(newProof)).Encode()),check);});assertions++;
        JournalHistory timeRotated=Add(identity,authority,preparedTime,JournalKind.TrustChanged,timeRecord.Encode());state=HostedTrustState.Replay(identity,intent,timeRotated,check);
        Require(state.Generation==2 && Wire.Equal(state.ForRelease().TimeKey,newTime) && state.Endpoint==timeChange.Endpoint);assertions++;
        byte[] cancellationProof=TimeProof(identity,timeChange,'6');TrustCancellation cancellation=new TrustCancellation(Wire.Hash(timePreparation.Encode()),false,cancellationProof,time(cancellationProof));
        HostedTrustState cancelledState=HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustCancelled,cancellation.Encode()),check);
        Require(cancelledState.Pending==null && cancelledState.Generation==2 && !cancelledState.TimeRevoked && cancelledState.SourceSha256!=afterPublisher.SourceSha256 && Wire.Equal(cancelledState.CurrentIdentity.TimeKey,identity.TimeKey));assertions++;
        Refuse(delegate {cancelledState.Validate(timeChange,newPublisherSign(timeChange.SigningInput()),zeros);});assertions++;
        TrustCancellation quarantine=new TrustCancellation(Wire.Hash(timePreparation.Encode()),true,cancellationProof,newTimeSign(cancellationProof));
        HostedTrustState quarantined=HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustCancelled,quarantine.Encode()),check);
        Require(quarantined.Pending==null && quarantined.Generation==2 && quarantined.TimeRevoked && Wire.Equal(quarantined.CurrentIdentity.TimeKey,identity.TimeKey));assertions++;
        Refuse(delegate {quarantined.ForRelease();});assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustCancelled,new TrustCancellation(H('1'),false,cancellationProof,time(cancellationProof)).Encode()),check);});assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,preparedTime,JournalKind.TrustCancelled,new TrustCancellation(Wire.Hash(timePreparation.Encode()),true,cancellationProof,time(cancellationProof)).Encode()),check);});assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,Add(identity,authority,rotated,JournalKind.TrustCancelled,cancellation.Encode()),check);});assertions++;
        Require(Wire.Equal(TrustPreparation.Decode(timePreparation.Encode()).Encode(),timePreparation.Encode()) && Wire.Equal(TrustCancellation.Decode(cancellation.Encode()).Encode(),cancellation.Encode()));assertions++;
        AuthorityIdentity cleanup=state.ForCleanup(H('a'));Require(Wire.Equal(cleanup.ReleaseKey,identity.ReleaseKey) && Wire.Equal(cleanup.TimeKey,newTime));assertions++;
        Refuse(delegate {TrustChange reuse=new TrustChange(1,identity.Installation,3,state.SourceSha256,1,10000,identity.ReleaseKey,newTime,state.Endpoint);state.Validate(reuse,newPublisherSign(reuse.SigningInput()),publisher(reuse.AcceptanceInput()));});assertions++;
        Refuse(delegate {TrustChange substitution=new TrustChange(3,identity.Installation,3,state.SourceSha256,1,10000,newPublisher,newTime,"https://time.example.invalid/luma/unreviewed");state.Validate(substitution,zeros,zeros);});assertions++;
        Refuse(delegate {new TrustRecord(timeChange,newPublisherSign(timeChange.SigningInput()),zeros,empty,empty,newProof,newTimeSign(newProof));});assertions++;
        TrustChange revokePublisher=new TrustChange(3,identity.Installation,3,state.SourceSha256,1,10000,newPublisher,newTime,state.Endpoint);oldProof=TimeProof(identity,revokePublisher,'e');
        JournalHistory pubRevoked=Add(identity,authority,timeRotated,JournalKind.TrustChanged,new TrustRecord(revokePublisher,zeros,zeros,oldProof,newTimeSign(oldProof),empty,empty).Encode());
        state=HostedTrustState.Replay(identity,intent,pubRevoked,check);Require(state.PublisherRevoked && !state.TimeRevoked);assertions++;Refuse(delegate {state.ForRelease();});assertions++;
        TrustChange recoverPub=new TrustChange(5,identity.Installation,4,state.SourceSha256,1,10000,recoveryPublisher,newTime,state.Endpoint);oldProof=TimeProof(identity,recoverPub,'f');
        JournalHistory recoveredPub=Add(identity,authority,pubRevoked,JournalKind.TrustChanged,new TrustRecord(recoverPub,zeros,recoveryPublisherSign(recoverPub.AcceptanceInput()),oldProof,newTimeSign(oldProof),empty,empty).Encode());
        Require(!HostedTrustState.Replay(identity,intent,recoveredPub,check).PublisherRevoked);assertions++;
        TrustChange revokeTime=new TrustChange(4,identity.Installation,4,state.SourceSha256,1,10000,newPublisher,newTime,state.Endpoint);oldProof=TimeProof(identity,revokeTime,'1');
        JournalHistory bothRevoked=Add(identity,authority,pubRevoked,JournalKind.TrustChanged,new TrustRecord(revokeTime,zeros,zeros,oldProof,newTimeSign(oldProof),empty,empty).Encode());
        state=HostedTrustState.Replay(identity,intent,bothRevoked,check);Require(state.PublisherRevoked && state.TimeRevoked);assertions++;Refuse(delegate {state.ForCleanup(H('a'));});assertions++;
        TrustChange recoverBoth=new TrustChange(7,identity.Installation,5,state.SourceSha256,1,10000,recoveryPublisher,recoveryTime,"https://time.example.invalid/luma/recovered");newProof=TimeProof(identity,recoverBoth,'2');
        JournalHistory recovered=Add(identity,authority,bothRevoked,JournalKind.TrustChanged,new TrustRecord(recoverBoth,zeros,recoveryPublisherSign(recoverBoth.AcceptanceInput()),empty,empty,newProof,recoveryTimeSign(newProof)).Encode());
        HostedTrustState result=HostedTrustState.Replay(identity,intent,recovered,check);Require(!result.PublisherRevoked && !result.TimeRevoked && Wire.Equal(result.ForRelease().ReleaseKey,recoveryPublisher));assertions++;
        Refuse(delegate {state.Validate(new TrustChange(7,identity.Installation,5,state.SourceSha256,1,10000,newPublisher,newTime,state.Endpoint),zeros,zeros);});assertions++;
        TrustChange onlyTimeRevocation=new TrustChange(4,identity.Installation,3,afterPublisher.SourceSha256,1,10000,newPublisher,newTime,timeChange.Endpoint);
        // This descriptor deliberately names the pre-time-change predecessor;
        // accepting it would allow a trust floor rollback.
        Refuse(delegate {HostedTrustState.Replay(identity,intent,timeRotated,check).Validate(onlyTimeRevocation,zeros,zeros);});assertions++;
        HostedTrustState timeBase=HostedTrustState.Replay(identity,intent,timeRotated,check);
        onlyTimeRevocation=new TrustChange(4,identity.Installation,3,timeBase.SourceSha256,1,10000,newPublisher,newTime,timeBase.Endpoint);oldProof=TimeProof(identity,onlyTimeRevocation,'3');
        JournalHistory onlyTimeHistory=Add(identity,authority,timeRotated,JournalKind.TrustChanged,new TrustRecord(onlyTimeRevocation,zeros,zeros,oldProof,newTimeSign(oldProof),empty,empty).Encode());
        HostedTrustState onlyTimeState=HostedTrustState.Replay(identity,intent,onlyTimeHistory,check);TrustChange recoverOnlyTime=new TrustChange(6,identity.Installation,4,onlyTimeState.SourceSha256,1,10000,newPublisher,recoveryTime,"https://time.example.invalid/luma/recovered");newProof=TimeProof(identity,recoverOnlyTime,'4');
        JournalHistory recoveredTime=Add(identity,authority,onlyTimeHistory,JournalKind.TrustChanged,new TrustRecord(recoverOnlyTime,newPublisherSign(recoverOnlyTime.SigningInput()),zeros,empty,empty,newProof,recoveryTimeSign(newProof)).Encode());
        Require(!HostedTrustState.Replay(identity,intent,recoveredTime,check).TimeRevoked);assertions++;
        Refuse(delegate {HostedTrustState.Replay(identity,intent,recovered,delegate {throw new SecurityException("Actual trust replay cancellation.");});});assertions++;
        LiveUtcWindow live=new LiveUtcWindow(identity,H('1'),1,2000);TimeAttestation proof=new TimeAttestation(identity.Installation,live.Nonce,H('1'),1000,1001);live.Accept(proof.Encode(),time(proof.Encode()));live.Check();assertions++;
        Refuse(delegate {live.Accept(proof.Encode(),time(proof.Encode()));});assertions++;
        LiveUtcWindow delayed=new LiveUtcWindow(identity,H('2'),1,1050);TimeAttestation delayedProof=new TimeAttestation(identity.Installation,delayed.Nonce,H('2'),1000,1001);System.Threading.Thread.Sleep(100);
        Refuse(delegate {delayed.Accept(delayedProof.Encode(),time(delayedProof.Encode()));});assertions++;
        return assertions;
    }
    public static int RunCompute(AuthorityIdentity identity,Func<byte[],byte[]> sign,string workspace) {
        int assertions=0;
        foreach(string operation in new string[]{"capture","reopen","spreadsheet","document","diagram","animation","collection"}) {
            GuestComputeRequest item=new GuestComputeRequest(operation,"{\"text\":\"native \\\"data\\\"\\n\"}");
            Require(Wire.Equal(HostedComputeContract.Decode(item.Bytes).Bytes,item.Bytes));assertions++;
        }
        GuestComputeRequest request=new GuestComputeRequest("capture","{\"text\":\"inert\"}");string raw=System.Text.Encoding.UTF8.GetString(request.Bytes);
        foreach(string changed in new string[]{raw+" "," "+raw,raw.Replace("\"schema_version\":1","\"schema_version\":true"),raw.Replace("\"schema_version\":1","\"schema_version\":1,\"schema_version\":1"),
            raw.Replace(GuestComputeRequest.Profile,"untrusted-profile"),raw.Replace(request.PayloadSha256,H('f')),raw.Replace("\"operation\":\"capture\"","\"operation\":\"inference\""),raw.Replace("\"nonce\":\""+request.Nonce+"\"","\"nonce\":\""+Zero+"\"")}) {
            Refuse(delegate {HostedComputeContract.Decode(System.Text.Encoding.UTF8.GetBytes(changed));});assertions++;
        }
        foreach(string denied in new string[]{"inference","shell","execute","publish","hosted-windows-compute-launch"}) {Refuse(delegate {new GuestComputeRequest(denied,"{}");});assertions++;}
        Refuse(delegate {HostedComputeContract.Decode(new GuestComputeRequest("capture",new string('\u00e9',2049)).Bytes);});assertions++;
        Refuse(delegate {HostedComputeContract.Decode(new GuestComputeRequest("capture",new string('\u0001',4096)).Bytes);});assertions++;
        DeploymentEvent admission=new DeploymentEvent(3,H('1'),1,request.RequestSha256,17,"ticket-package-"+new string('b',32)+".tar",0,0,0,Zero);
        byte[] review=HostedComputeContract.ReviewBytes(admission,request,H('a'));Require(HostedComputeContract.ValidateReview(review,request,H('1')).Generation==request.RequestSha256);assertions++;
        Refuse(delegate {HostedComputeContract.ValidateReview(review,new GuestComputeRequest("capture","{\"text\":\"inert\"}"),H('1'));});assertions++;
        Refuse(delegate {HostedComputeContract.ValidateReview(review,request,H('2'));});assertions++;
        Refuse(delegate {HostedComputeContract.ReviewBytes(Event(2,'1',1,'a','b',0,0,0,'0'),request,H('a'));});assertions++;
        Transition[] activation={T(JournalKind.ImportPrepared,Event(1,'1',1,'a','b',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(1,'1',1,'a','b',42,99,0,'0')),
            T(JournalKind.ControllerCompleted,Event(1,'1',1,'a','b',42,99,1,'c')),T(JournalKind.Imported,Event(1,'1',1,'a','b',0,0,1,'c')),
            T(JournalKind.ActivationPrepared,Event(2,'1',1,'d','b',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(2,'1',1,'d','b',43,100,0,'0')),
            T(JournalKind.ControllerCompleted,Event(2,'1',1,'d','b',43,100,1,'e')),T(JournalKind.Activated,Event(2,'1',1,'d','b',0,0,1,'e'))};
        DeploymentEvent prepare=Event(3,'1',1,'e','b',0,0,0,'0'),start=Event(3,'1',1,'e','b',44,101,0,'0'),done=Event(3,'1',1,'e','b',44,101,1,'f'),observed=Event(3,'1',1,'e','b',0,0,1,'f'),cancelled=Event(3,'1',1,'e','b',0,0,2,'c');
        Func<Transition[],JournalHistory> computeHistory=delegate(Transition[] tail) {List<Transition> list=new List<Transition>(activation);list.AddRange(tail);return History(identity,sign,list.ToArray());};
        JournalHistory success=computeHistory(new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.ComputeObserved,observed)});
        DeploymentHistory state=DeploymentHistory.Replay(success);Require(state.Active.Purpose==2 && state.Active.Generation==H('d') && state.Pending==null);assertions++;
        HostedComputeContract.RequireAdmissionCapacity(success);assertions++;
        byte[][] originalPrefix=new byte[success.Entries.Length-4][];for(int index=0;index<originalPrefix.Length;index++) originalPrefix[index]=success.Entries[index].Bytes;
        JournalHistory activeHistory=JournalHistory.Replay(identity,originalPrefix);HostedComputeHead held=new HostedComputeHead(identity,activeHistory,activeHistory.Head);held.Require(activeHistory.Head);assertions++;
        Refuse(delegate {new HostedComputeHead(identity,activeHistory,H('9'));});assertions++;
        JournalEntry accepted=success.Entries[activeHistory.Entries.Length];held.Advance(accepted);held.Require(accepted.NextHead);assertions++;
        Refuse(delegate {held.Require(activeHistory.Head);});assertions++;Refuse(delegate {held.Require(H('9'));});assertions++;
        Refuse(delegate {held.Advance(accepted);});assertions++;
        Refuse(delegate {held.Advance(JournalEntry.Prepare(identity,accepted.Sequence+1,JournalKind.ComputeObserved,accepted.NextHead,accepted.RecordSha256,identity.FirstAdminSid,observed.Encode()));});assertions++;
        held.Advance(success.Entries[activeHistory.Entries.Length+1]);held.Require(success.Entries[activeHistory.Entries.Length+1].NextHead);assertions++;
        List<Transition> nearLimit=new List<Transition>(activation);
        for(uint index=0;index<252;index++) {
            string generation=(index+1).ToString("x64");Func<uint,ulong,byte,string,DeploymentEvent> bound=delegate(uint process,ulong creation,byte outcome,string digest) {return new DeploymentEvent(3,H('1'),1,generation,17,"ticket-package-"+new string('b',32)+".tar",process,creation,outcome,digest);};
            nearLimit.Add(T(JournalKind.ComputePrepared,bound(0,0,0,Zero)));nearLimit.Add(T(JournalKind.ControllerStarted,bound(1000+index,10000+index,0,Zero)));
            nearLimit.Add(T(JournalKind.ControllerCompleted,bound(1000+index,10000+index,1,H('f'))));nearLimit.Add(T(JournalKind.ComputeObserved,bound(0,0,1,H('f'))));
            if(index==250) {JournalHistory available=History(identity,sign,nearLimit.ToArray());Require(DeploymentHistory.Replay(available).Pending==null);HostedComputeContract.RequireAdmissionCapacity(available);assertions++;}
        }
        JournalHistory exhausted=History(identity,sign,nearLimit.ToArray());Require(DeploymentHistory.Replay(exhausted).Pending==null);Refuse(delegate {HostedComputeContract.RequireAdmissionCapacity(exhausted);});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ComputePrepared,prepare)));});assertions++;
        foreach(DeploymentEvent wrong in new DeploymentEvent[]{Event(3,'2',1,'e','b',0,0,0,'0'),Event(3,'1',2,'e','b',0,0,0,'0'),Event(3,'1',1,'e','f',0,0,0,'0'),Event(2,'1',1,'e','b',0,0,0,'0')}) {
            Refuse(delegate {DeploymentHistory.Replay(computeHistory(new Transition[]{T(JournalKind.ComputePrepared,wrong)}));});assertions++;
        }
        foreach(Transition[] invalid in new Transition[][] {
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ComputeObserved,observed)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerCompleted,done)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.Cancelled,cancelled)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.ControllerStarted,start)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.Activated,observed)},
            new Transition[]{T(JournalKind.ImportPrepared,prepare)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ComputePrepared,prepare)},
            new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,Event(3,'1',1,'e','b',44,102,1,'f'))}}) {
            Refuse(delegate {DeploymentHistory.Replay(computeHistory(invalid));});assertions++;
        }
        JournalHistory recovered=computeHistory(new Transition[]{T(JournalKind.ComputePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,Event(3,'1',1,'e','b',44,101,2,'c')),T(JournalKind.Cancelled,cancelled)});
        Require(DeploymentHistory.Replay(recovered).Pending==null && DeploymentHistory.Replay(recovered).Active.Generation==H('d'));assertions++;
        JournalHistory pending=computeHistory(new Transition[]{T(JournalKind.ComputePrepared,prepare)});
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,pending,JournalKind.TrustChanged,new byte[]{1}));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,pending,JournalKind.RuntimePrepared,new byte[]{1}));});assertions++;
        byte[] content=new byte[65537];for(int index=0;index<content.Length;index++) content[index]=unchecked((byte)index);
        HostedComputeDelivery delivery=new HostedComputeDelivery(H('a'),request.RequestSha256,content);
        using(HostedComputeReceiver receiver=new HostedComputeReceiver(request.RequestSha256)) {
            Refuse(delegate {receiver.Part(delivery.Next());});assertions++;
            delivery.Clear();delivery=new HostedComputeDelivery(H('a'),request.RequestSha256,content);receiver.Reviewed(H('a'));
            Refuse(delegate {delivery.Receipt(H('b'));});assertions++;Refuse(delegate {receiver.ResultBase64();});assertions++;
            while(!delivery.Complete) {byte[] chunk=delivery.Next();Refuse(delegate {delivery.Next();});assertions++;byte[] ack=receiver.Part(chunk);byte[] wrong=(byte[])ack.Clone();wrong[wrong.Length-1]^=1;Refuse(delegate {delivery.Acknowledge(wrong);});assertions++;delivery.Acknowledge(ack);assertions++;}
            byte[] receipt=delivery.Receipt(H('b'));receiver.Finish(receipt);Require(receiver.ResultBase64()==Convert.ToBase64String(content));assertions++;
            Refuse(delegate {receiver.Finish(receipt);});assertions++;Refuse(delegate {receiver.Reviewed(H('a'));});assertions++;Refuse(delegate {delivery.Next();});assertions++;
        }delivery.Clear();
        foreach(int changedOffset in new int[]{0,90,140}) {
            HostedComputeDelivery candidate=new HostedComputeDelivery(H('a'),request.RequestSha256,new byte[]{1,2,3});using(HostedComputeReceiver receiver=new HostedComputeReceiver(request.RequestSha256)) {
                receiver.Reviewed(H('a'));byte[] chunk=candidate.Next();chunk[changedOffset]^=1;Refuse(delegate {receiver.Part(chunk);});assertions++;
            }candidate.Clear();
        }
        HostedComputeDelivery authorityClaim=new HostedComputeDelivery(H('a'),request.RequestSha256,new byte[]{1});using(HostedComputeReceiver receiver=new HostedComputeReceiver(request.RequestSha256)) {
            receiver.Reviewed(H('a'));authorityClaim.Acknowledge(receiver.Part(authorityClaim.Next()));byte[] receipt=authorityClaim.Receipt(H('b'));receipt[receipt.Length-1]=1;Refuse(delegate {receiver.Finish(receipt);});assertions++;
        }authorityClaim.Clear();
        string parent=Path.Combine(Path.GetFullPath(workspace),".luma"),root=Path.Combine(parent,"windows-compute-fixtures-"+Guid.NewGuid().ToString("N"));
        if(new DriveInfo(Path.GetPathRoot(root)).DriveFormat!="NTFS" || (File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0) throw new Exception("Actual tiny nonlinked NTFS compute fixture required.");
        Directory.CreateDirectory(root);string file=Path.Combine(root,"payload.json");File.WriteAllText(file,"{\"text\":\"inert\"}",new System.Text.UTF8Encoding(false,true));
        try {
            Type type=typeof(HostedComputeContract).Assembly.GetType("Luma.Windows.Hosted.HostedComputeInputs",true);object original=Activator.CreateInstance(type,BindingFlags.NonPublic|BindingFlags.Instance,null,new object[]{new string[]{"compute",H('1'),"capture",file}},null);
            using((IDisposable)original) {KernelRefuse(delegate {File.WriteAllText(file,"{}");});assertions++;KernelRefuse(delegate {File.Move(file,file+".moved");});assertions++;
                try {type.GetMethod("Check",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(original,null);}catch(TargetInvocationException error) {throw error.InnerException;}assertions++;
                FileSecurity before=File.GetAccessControl(file,AccessControlSections.Access);
                try {
                    FileSecurity changed=new FileSecurity();changed.SetSecurityDescriptorBinaryForm(before.GetSecurityDescriptorBinaryForm(),AccessControlSections.Access);changed.SetAccessRuleProtection(true,true);changed.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),FileSystemRights.Read,AccessControlType.Allow));File.SetAccessControl(file,changed);
                    Refuse(delegate {try {type.GetMethod("Check",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(original,null);}catch(TargetInvocationException error) {throw error.InnerException;}});assertions++;
                }finally {FileSecurity restored=new FileSecurity();restored.SetSecurityDescriptorBinaryForm(before.GetSecurityDescriptorBinaryForm(),AccessControlSections.Access);File.SetAccessControl(file,restored);}
                type.GetField("cancelled",BindingFlags.NonPublic|BindingFlags.Instance).SetValue(original,1);bool cancelObserved=false;
                try {type.GetMethod("Check",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(original,null);}catch(TargetInvocationException error) {if(!(error.InnerException is OperationCanceledException)) throw;cancelObserved=true;}
                Require(cancelObserved);assertions++;
            }
            File.WriteAllBytes(file,new byte[4097]);Refuse(delegate {try {using((IDisposable)Activator.CreateInstance(type,BindingFlags.NonPublic|BindingFlags.Instance,null,new object[]{new string[]{"compute",H('1'),"capture",file}},null)) {}}catch(TargetInvocationException error) {throw error.InnerException;}});assertions++;
        }finally {string resolved=Path.GetFullPath(root);if(Path.GetDirectoryName(resolved)!=parent || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(resolved),"\\Awindows-compute-fixtures-[0-9a-f]{32}\\z")) throw new Exception("Refuse cleanup outside exact new compute fixture.");Directory.Delete(resolved,true);}
        return assertions;
    }
    public static int RunInference(AuthorityIdentity identity,Func<byte[],byte[]> sign) {
        int assertions=0;GuestInferenceRequest request=new GuestInferenceRequest(H('7'),H('8'),"Exact private prompt\n\u00e9",128);
        Require(Wire.Equal(GuestInferenceRequest.Decode(request.Bytes).Bytes,request.Bytes));assertions++;
        Require(request.RequestSha256!=request.PromptSha256 && request.MaximumTokens==128);assertions++;
        GuestInferenceRequest escaped=new GuestInferenceRequest(H('7'),H('8'),new string('\u0001',4096),512);
        Require(escaped.Bytes.Length>8192 && Wire.Equal(GuestInferenceRequest.Decode(escaped.Bytes).Bytes,escaped.Bytes));assertions++;
        foreach(string denied in new string[]{"",new string('x',4097),new string('\u00e9',2049),"x\0y","\ud800"}) {Refuse(delegate {new GuestInferenceRequest(H('7'),H('8'),denied,128);});assertions++;}
        foreach(uint denied in new uint[]{0,513,UInt32.MaxValue}) {Refuse(delegate {new GuestInferenceRequest(H('7'),H('8'),"x",denied);});assertions++;}
        string raw=System.Text.Encoding.UTF8.GetString(request.Bytes);
        foreach(string changed in new string[]{raw+"\n"," "+raw,raw.Replace("\"schema_version\":1","\"schema_version\":true"),raw.Replace("\"schema_version\":1","\"schema_version\":1,\"schema_version\":1"),
            raw.Replace(GuestInferenceRequest.Profile,GuestComputeRequest.Profile),raw.Replace(GuestInferenceRequest.ModelSha256,H('9')),raw.Replace(request.PromptSha256,H('a')),
            raw.Replace("\"context_tokens\":2048","\"context_tokens\":4096"),raw.Replace("\"nonce\":\""+request.Nonce+"\"","\"nonce\":\""+Zero+"\""),raw.Replace("\"max_tokens\":128","\"max_tokens\":128,\"operation\":\"shell\"")}) {
            Refuse(delegate {GuestInferenceRequest.Decode(System.Text.Encoding.UTF8.GetBytes(changed));});assertions++;
        }
        DeploymentEvent admission=new DeploymentEvent(4,H('1'),1,request.RequestSha256,17,"ticket-package-"+new string('b',32)+".tar",0,0,0,Zero);
        byte[] review=HostedInferenceContract.ReviewBytes(admission,request,H('a'));Require(HostedInferenceContract.ValidateReview(review,request,H('1')).Generation==request.RequestSha256);assertions++;
        Refuse(delegate {HostedInferenceContract.ValidateReview(review,new GuestInferenceRequest(H('7'),H('8'),"Exact private prompt\n\u00e9",128),H('1'));});assertions++;
        Refuse(delegate {HostedInferenceContract.ValidateReview(review,request,H('2'));});assertions++;
        Refuse(delegate {HostedInferenceContract.ReviewBytes(Event(3,'1',1,'a','b',0,0,0,'0'),request,H('a'));});assertions++;
        Transition[] activation={T(JournalKind.ImportPrepared,Event(1,'1',1,'a','b',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(1,'1',1,'a','b',42,99,0,'0')),
            T(JournalKind.ControllerCompleted,Event(1,'1',1,'a','b',42,99,1,'c')),T(JournalKind.Imported,Event(1,'1',1,'a','b',0,0,1,'c')),
            T(JournalKind.ActivationPrepared,Event(2,'1',1,'d','b',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(2,'1',1,'d','b',43,100,0,'0')),
            T(JournalKind.ControllerCompleted,Event(2,'1',1,'d','b',43,100,1,'e')),T(JournalKind.Activated,Event(2,'1',1,'d','b',0,0,1,'e'))};
        DeploymentEvent prepare=Event(4,'1',1,'e','b',0,0,0,'0'),start=Event(4,'1',1,'e','b',44,101,0,'0'),done=Event(4,'1',1,'e','b',44,101,1,'f'),observed=Event(4,'1',1,'e','b',0,0,1,'f'),cancelled=Event(4,'1',1,'e','b',0,0,2,'c');
        Func<Transition[],JournalHistory> history=delegate(Transition[] tail) {List<Transition> list=new List<Transition>(activation);list.AddRange(tail);return History(identity,sign,list.ToArray());};
        JournalHistory success=history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.InferenceObserved,observed)});
        DeploymentHistory state=DeploymentHistory.Replay(success);Require(state.Pending==null && state.Active.Purpose==2 && state.Active.Generation==H('d'));assertions++;
        int staged=0;Refuse(delegate {state.RequireFreshGeneration(prepare.Generation);staged++;});Require(staged==0);assertions+=2;
        state.RequireFreshGeneration(H('9'));assertions++;
        JournalEntry repeated=JournalEntry.Prepare(identity,success.Sequence+1,JournalKind.InferencePrepared,success.Head,success.Record,identity.FirstAdminSid,prepare.Encode());repeated=repeated.Signed(identity,sign(repeated.SigningInput));
        Refuse(delegate {DeploymentHistory.ValidateNext(identity,success,repeated,delegate { });staged++;});Require(staged==0 && success.Sequence==13 && DeploymentHistory.Replay(success).Pending==null);assertions+=2;
        HostedComputeContract.RequireAdmissionCapacity(success);assertions++;
        foreach(Transition[] bad in new Transition[][] {
            new Transition[]{T(JournalKind.ComputePrepared,prepare)},new Transition[]{T(JournalKind.InferencePrepared,Event(3,'1',1,'e','b',0,0,0,'0'))},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.InferenceObserved,observed)},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.InferenceObserved,observed)},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.Cancelled,cancelled)},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.ComputeObserved,observed)},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.ControllerStarted,start)},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.InferencePrepared,prepare)},
            new Transition[]{T(JournalKind.InferencePrepared,Event(4,'2',1,'e','b',0,0,0,'0'))},new Transition[]{T(JournalKind.InferencePrepared,Event(4,'1',1,'e','f',0,0,0,'0'))},
            new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,Event(4,'1',1,'e','b',44,102,1,'f'))}}) {
            Refuse(delegate {DeploymentHistory.Replay(history(bad));});assertions++;
        }
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.InferencePrepared,prepare)));});assertions++;
        JournalHistory pending=history(new Transition[]{T(JournalKind.InferencePrepared,prepare)});
        Require(DeploymentHistory.Replay(pending).DrainRequestSha256()==prepare.Generation);assertions++;
        DeploymentEvent boundStart=Event(4,'1',1,'e','b',44,101,0,'e');
        JournalHistory runningBound=history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,boundStart)});
        Require(DeploymentHistory.Replay(runningBound).DrainRequestSha256()==H('e'));assertions++;
        JournalHistory completedBound=history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,boundStart),T(JournalKind.ControllerCompleted,done)});
        Require(DeploymentHistory.Replay(completedBound).Worker==null && DeploymentHistory.Replay(completedBound).LastControllerRequestSha256==H('e') && DeploymentHistory.Replay(completedBound).DrainRequestSha256()==H('e'));assertions++;
        Refuse(delegate {DeploymentHistory.Replay(history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,Event(4,'1',1,'e','b',44,101,0,'f'))}));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start)})).DrainRequestSha256();});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,boundStart),T(JournalKind.ControllerCompleted,boundStart)}));});assertions++;
        List<Transition> next=new List<Transition>(activation);
        next.AddRange(new Transition[]{T(JournalKind.ImportPrepared,Event(1,'2',2,'8','f',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(1,'2',2,'8','f',50,200,0,'0')),
            T(JournalKind.ControllerCompleted,Event(1,'2',2,'8','f',50,200,1,'c')),T(JournalKind.Imported,Event(1,'2',2,'8','f',0,0,1,'c')),
            T(JournalKind.ActivationPrepared,Event(2,'2',2,'9','f',0,0,0,'0')),T(JournalKind.ControllerStarted,Event(2,'2',2,'9','f',51,201,0,'7')),
            T(JournalKind.ControllerCompleted,Event(2,'2',2,'9','f',51,201,2,'c'))});
        DeploymentHistory continued=DeploymentHistory.Replay(History(identity,sign,next.ToArray()));Require(continued.Pending.Generation==H('9') && continued.Worker==null && continued.DrainRequestSha256()==H('7'));assertions++;
        next.Add(T(JournalKind.ControllerStarted,Event(2,'2',2,'9','f',52,202,0,'6')));
        continued=DeploymentHistory.Replay(History(identity,sign,next.ToArray()));Require(continued.Pending.Generation==H('9') && continued.DrainRequestSha256()==H('6'));assertions++;
        next.Add(T(JournalKind.ControllerCompleted,Event(2,'2',2,'9','f',52,202,1,'c')));next.Add(T(JournalKind.Activated,Event(2,'2',2,'9','f',0,0,1,'c')));
        continued=DeploymentHistory.Replay(History(identity,sign,next.ToArray()));Require(continued.Pending==null && continued.Active.ReleaseSequence==2);assertions++;
        foreach(JournalKind denied in new JournalKind[]{JournalKind.TrustChanged,JournalKind.RuntimePrepared,JournalKind.FileEnrolled}) {Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,pending,denied,new byte[]{1}));});assertions++;}
        JournalHistory recovered=history(new Transition[]{T(JournalKind.InferencePrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,Event(4,'1',1,'e','b',44,101,2,'c')),T(JournalKind.Cancelled,cancelled)});
        Require(DeploymentHistory.Replay(recovered).Pending==null && DeploymentHistory.Replay(recovered).Active.Generation==H('d'));assertions++;
        byte[] result=new byte[70000];for(int index=0;index<result.Length;index++) result[index]=(byte)('a'+index%26);string reviewHash=Wire.Hash(review);
        HostedInferenceDelivery delivery=new HostedInferenceDelivery(reviewHash,request.RequestSha256,result);
        using(HostedInferenceReceiver receiver=new HostedInferenceReceiver(request.RequestSha256)) {
            Refuse(delegate {receiver.Part(delivery.Next());});assertions++;
        }
        delivery.Clear();delivery=new HostedInferenceDelivery(reviewHash,request.RequestSha256,result);
        using(HostedInferenceReceiver receiver=new HostedInferenceReceiver(request.RequestSha256)) {
            receiver.Reviewed(reviewHash);Refuse(delegate {receiver.Reviewed(reviewHash);});assertions++;
            Refuse(delegate {delivery.Receipt(H('f'));});assertions++;
            Refuse(delegate {receiver.ResultBase64();});assertions++;
            while(!delivery.Complete) {byte[] part=delivery.Next();Refuse(delegate {delivery.Next();});assertions++;byte[] ack=receiver.Part(part);byte[] bad=(byte[])ack.Clone();bad[bad.Length-1]^=1;
                Refuse(delegate {delivery.Acknowledge(bad);});assertions++;delivery.Acknowledge(ack);assertions++;}
            receiver.Finish(delivery.Receipt(H('f')));Require(receiver.Complete && Wire.Equal(Convert.FromBase64String(receiver.ResultBase64()),result));assertions++;
            Refuse(delegate {receiver.Finish(delivery.Receipt(H('f')));});assertions++;
            Refuse(delegate {delivery.Next();});assertions++;
        }delivery.Clear();
        using(HostedComputeReceiver wrong=new HostedComputeReceiver(request.RequestSha256)) {wrong.Reviewed(reviewHash);HostedInferenceDelivery distinct=new HostedInferenceDelivery(reviewHash,request.RequestSha256,result);Refuse(delegate {wrong.Part(distinct.Next());});assertions++;distinct.Clear();}
        return assertions;
    }
    public static int Run(AuthorityIdentity identity,Func<byte[],byte[]> sign) {
        int assertions=0;
        DeploymentEvent prepare=Event(1,'1',1,'a','b',0,0,0,'0'),start=Event(1,'1',1,'a','b',42,99,0,'0'),
            done=Event(1,'1',1,'a','b',42,99,1,'c'),imported=Event(1,'1',1,'a','b',0,0,1,'c');
        Transition[] import={T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.Imported,imported)};
        DeploymentHistory state=DeploymentHistory.Replay(History(identity,sign,import));Require(state.Pending==null && state.Active==null && state.Imported(H('1'))!=null);assertions++;
        Require(Wire.Equal(DeploymentEvent.Decode(prepare.Encode()).Encode(),prepare.Encode()));assertions++;
        byte[] extra=new byte[prepare.Encode().Length+1];Array.Copy(prepare.Encode(),extra,extra.Length-1);Refuse(delegate {DeploymentEvent.Decode(extra);});assertions++;
        Refuse(delegate {Event(5,'1',1,'a','b',0,0,0,'0');});assertions++;
        Refuse(delegate {Event(1,'1',1,'a','b',42,0,0,'0');});assertions++;
        Refuse(delegate {Event(1,'1',1,'a','b',0,0,1,'0');});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.Imported,imported)));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ControllerStarted,start)));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerCompleted,done)));});assertions++;
        foreach(DeploymentEvent changed in new DeploymentEvent[] {
            Event(2,'1',1,'a','b',42,99,0,'0'),Event(1,'2',1,'a','b',42,99,0,'0'),Event(1,'1',2,'a','b',42,99,0,'0'),
            Event(1,'1',1,'d','b',42,99,0,'0'),Event(1,'1',1,'a','e',42,99,0,'0'),
            new DeploymentEvent(1,H('1'),1,H('a'),18,"ticket-package-"+new string('b',32)+".tar",42,99,0,Zero)}) {
            Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,changed)));});assertions++;
        }
        foreach(DeploymentEvent changed in new DeploymentEvent[] {Event(1,'1',1,'a','b',43,99,1,'c'),Event(1,'1',1,'a','b',42,100,1,'c')}) {
            Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,changed)));});assertions++;
        }
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,Event(1,'1',1,'a','b',42,99,2,'c')),T(JournalKind.Imported,imported)));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.Imported,Event(1,'1',1,'a','b',0,0,1,'d'))));});assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ImportPrepared,prepare),T(JournalKind.ControllerStarted,start),T(JournalKind.ControllerCompleted,done),T(JournalKind.ControllerStarted,start)));});assertions++;
        DeploymentEvent activation=Event(2,'1',1,'d','b',0,0,0,'0'),aStart=Event(2,'1',1,'d','b',43,100,0,'0'),aDone=Event(2,'1',1,'d','b',43,100,1,'e'),active=Event(2,'1',1,'d','b',0,0,1,'e');
        List<Transition> activated=new List<Transition>(import);activated.Add(T(JournalKind.ActivationPrepared,activation));activated.Add(T(JournalKind.ControllerStarted,aStart));activated.Add(T(JournalKind.ControllerCompleted,aDone));activated.Add(T(JournalKind.Activated,active));
        state=DeploymentHistory.Replay(History(identity,sign,activated.ToArray()));Require(state.Active.ReleaseSha256==H('1') && state.Pending==null);assertions++;
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,T(JournalKind.ActivationPrepared,activation)));});assertions++;
        List<Transition> wrongSlot=new List<Transition>(import);wrongSlot.Add(T(JournalKind.ActivationPrepared,Event(2,'1',1,'d','f',0,0,0,'0')));
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,wrongSlot.ToArray()));});assertions++;
        List<Transition> retry=new List<Transition>(activated);retry.Add(T(JournalKind.ImportPrepared,Event(1,'2',2,'e','f',0,0,0,'0')));retry.Add(T(JournalKind.Cancelled,Event(1,'2',2,'e','f',0,0,2,'c')));retry.Add(T(JournalKind.ImportPrepared,Event(1,'2',2,'f','a',0,0,0,'0')));
        state=DeploymentHistory.Replay(History(identity,sign,retry.ToArray()));Require(state.Active.ReleaseSha256==H('1') && state.Pending.Generation==H('f'));assertions++;
        retry.RemoveAt(retry.Count-1);retry.Add(T(JournalKind.ImportPrepared,Event(1,'2',2,'e','a',0,0,0,'0')));
        Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,retry.ToArray()));});assertions++;
        List<Transition> budget=new List<Transition>(import);budget.Add(T(JournalKind.ActivationPrepared,activation));
        for(uint index=0;index<4;index++) {budget.Add(T(JournalKind.ControllerStarted,Event(2,'1',1,'d','b',43+index,100+index,0,'0')));budget.Add(T(JournalKind.ControllerCompleted,Event(2,'1',1,'d','b',43+index,100+index,2,'e')));}
        budget.Add(T(JournalKind.ControllerStarted,aStart));Refuse(delegate {DeploymentHistory.Replay(History(identity,sign,budget.ToArray()));});assertions++;
        JournalHistory genuine=History(identity,sign,import);Refuse(delegate {DeploymentHistory.Replay(genuine,delegate {throw new SecurityException("Actual continuous cancellation.");});});assertions++;
        Refuse(delegate {JournalHistory.Replay(identity,new byte[][]{genuine.Entries[0].Bytes},delegate {throw new SecurityException("Actual journal cancellation.");});});assertions++;
        TpmEpoch priorEpoch=new TpmEpoch(100,200,2,7,true),resetEpoch=new TpmEpoch(1,201,3,0,true);
        resetEpoch.RequireResetSince(priorEpoch,17,18);assertions++;
        Refuse(delegate {resetEpoch.RequireResetSince(priorEpoch,17,17);});assertions++;
        Refuse(delegate {new TpmEpoch(10000,20000,2,8,true).RequireResetSince(priorEpoch,17,18);});assertions++;
        Refuse(delegate {new TpmEpoch(1,201,1,100,true).RequireResetSince(priorEpoch,17,18);});assertions++;
        JournalEntry abandoned=JournalEntry.Prepare(identity,2,JournalKind.ImportPrepared,genuine.Entries[0].NextHead,genuine.Entries[0].RecordSha256,identity.FirstAdminSid,prepare.Encode());
        abandoned=abandoned.Signed(identity,sign(abandoned.SigningInput));
        byte[] dispatchInput=DispatchTicket.SigningInput(identity,abandoned,17,priorEpoch);
        DispatchTicket dispatch=DispatchTicket.Signed(identity,dispatchInput,sign(dispatchInput));dispatch.Matches(abandoned);
        Require(Wire.Equal(dispatch.Encode(),DispatchTicket.Decode(identity,dispatch.Encode()).Encode()));assertions++;
        Refuse(delegate {dispatch.Matches(genuine.Entries[0]);});assertions++;
        byte[] changedSignature=sign(dispatchInput);changedSignature[0]^=1;Refuse(delegate {DispatchTicket.Signed(identity,dispatchInput,changedSignature);});assertions++;
        NvAbortEvent abort=new NvAbortEvent(dispatch,18,resetEpoch,Wire.Bytes(H('e'),32,true));
        JournalEntry replacement=JournalEntry.Prepare(identity,2,JournalKind.NvWriteAborted,genuine.Entries[0].NextHead,genuine.Entries[0].RecordSha256,identity.FirstAdminSid,abort.Encode());replacement=replacement.Signed(identity,sign(replacement.SigningInput));
        abort.Matches(replacement);JournalHistory recovered=JournalHistory.Replay(identity,new byte[][]{genuine.Entries[0].Bytes,replacement.Bytes});
        Require(recovered.Sequence==2 && recovered.Head==replacement.NextHead && DeploymentHistory.Replay(recovered).Pending==null);assertions++;
        Refuse(delegate {abort.Matches(abandoned);});assertions++;
        Refuse(delegate {new NvAbortEvent(dispatch,18,new TpmEpoch(10000,20000,2,8,true),Wire.Bytes(H('e'),32,true));});assertions++;
        Refuse(delegate {new NvAbortEvent(dispatch,18,resetEpoch,new byte[32]);});assertions++;
        Require(Wire.Equal(abort.Encode(),NvAbortEvent.Decode(identity,abort.Encode()).Encode()));assertions++;
        CommissionIntent intent=new CommissionIntent(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,identity.ReleaseKey,identity.TimeKey,identity.ServiceSha256,identity.WslSha256,"https://time.example.invalid/luma/challenge",SoftwareBaseline(identity));
        JournalEntry first=JournalEntry.Prepare(identity,1,JournalKind.Commission,Zero,Zero,identity.FirstAdminSid,intent.GenesisPayload(identity));first=first.Signed(identity,sign(first.SigningInput));
        byte[] initialInput=DispatchTicket.SigningInput(identity,first,17,priorEpoch);DispatchTicket initial=DispatchTicket.Signed(identity,initialInput,sign(initialInput));
        NvAbortEvent initialAbort=new NvAbortEvent(initial,18,resetEpoch,Wire.Bytes(H('f'),32,true));
        JournalEntry freshFirst=JournalEntry.Prepare(identity,1,JournalKind.Commission,Zero,Zero,identity.FirstAdminSid,intent.RecoveredGenesisPayload(identity,initialAbort));freshFirst=freshFirst.Signed(identity,sign(freshFirst.SigningInput));
        initialAbort.Matches(freshFirst);intent.ValidateGenesis(identity,freshFirst.Payload);Require(JournalHistory.Replay(identity,new byte[][]{freshFirst.Bytes}).Sequence==1 && freshFirst.RecordSha256!=first.RecordSha256);assertions++;
        Refuse(delegate {intent.ValidateGenesis(identity,identity.Encode());});assertions++;
        Refuse(delegate {initialAbort.Matches(first);});assertions++;
        return assertions;
    }
}
'@
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $identity=[Luma.Windows.Hosted.AuthorityIdentity]::new('host-deployment',('ab'*32),$sid,'lab',
        $keys[0].PublicBlob(),$keys[1].PublicBlob(),$keys[2].PublicBlob(),('cd'*32),('ef'*32))
    $other=[Luma.Windows.Hosted.AuthorityIdentity]::new('content-authority',('ab'*32),$sid,'lab',
        $keys[0].PublicBlob(),$keys[1].PublicBlob(),$keys[3].PublicBlob(),('cd'*32),('ef'*32))
    $zero='0'*64
    $fixtureSigner={param([byte[]]$inputBytes) $keys[2].Sign($inputBytes)}
    $lifecycleAssertions=[LumaHostedLifecycleFixture]::Run($identity,$fixtureSigner)
    Assert-Hosted ($lifecycleAssertions -ge 25) 'Complete actual signed lifecycle regression group did not run.'
    $script:HostedAssertions+=$lifecycleAssertions
    $computeAssertions=[LumaHostedLifecycleFixture]::RunCompute($identity,$fixtureSigner,[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
    Assert-Hosted ($computeAssertions -ge 65) 'Complete actual signed compute lifecycle, original-client delivery and held NTFS regressions did not run.'
    $script:HostedAssertions+=$computeAssertions
    $inferenceAssertions=[LumaHostedLifecycleFixture]::RunInference($identity,$fixtureSigner)
    Assert-Hosted ($inferenceAssertions -ge 60) 'Complete exact signed inference lifecycle and separate bounded original-client delivery regressions did not run.'
    $script:HostedAssertions+=$inferenceAssertions
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),(Join-Path $build.work_directory 'Luma.PackageInspector.dll'),'System.dll','System.Core.dll','System.Security.dll') -Path (Join-Path $PSScriptRoot 'HostedAuthorityInferenceFixture.cs')
    $inferenceMechanismAssertions=[LumaHostedInferenceFixture]::Run([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
    Assert-Hosted ($inferenceMechanismAssertions -ge 80) 'Complete inference model/profile/closure, actual framing, confinement, cancellation and held NTFS tests did not run.'
    $script:HostedAssertions+=$inferenceMechanismAssertions
    $publisherSigner={param([byte[]]$inputBytes) $keys[0].Sign($inputBytes)}
    $timeSigner={param([byte[]]$inputBytes) $keys[1].Sign($inputBytes)}
    $newPublisherSigner={param([byte[]]$inputBytes) $keys[3].Sign($inputBytes)}
    $newTimeSigner={param([byte[]]$inputBytes) $keys[4].Sign($inputBytes)}
    $recoveryPublisherSigner={param([byte[]]$inputBytes) $keys[5].Sign($inputBytes)}
    $recoveryTimeSigner={param([byte[]]$inputBytes) $keys[6].Sign($inputBytes)}
    $trustAssertions=[LumaHostedLifecycleFixture]::RunTrust($identity,$fixtureSigner,$publisherSigner,$timeSigner,$keys[3].PublicBlob(),$newPublisherSigner,
        $keys[4].PublicBlob(),$newTimeSigner,$keys[5].PublicBlob(),$recoveryPublisherSigner,$keys[6].PublicBlob(),$recoveryTimeSigner)
    Assert-Hosted ($trustAssertions -ge 25) 'Complete actual signed trust lifecycle regression group did not run.'
    $script:HostedAssertions+=$trustAssertions
    $runtimeAssertions=[LumaHostedLifecycleFixture]::RunRuntime($identity,$fixtureSigner,$publisherSigner,$timeSigner,$keys[3].PublicBlob(),$newPublisherSigner)
    Assert-Hosted ($runtimeAssertions -ge 24) 'Complete actual signed runtime lifecycle regression group did not run.'
    $script:HostedAssertions+=$runtimeAssertions
    $ntfsAssertions=[LumaHostedLifecycleFixture]::RunInstalledLease([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
    Assert-Hosted ($ntfsAssertions -ge 10) 'Actual tiny NTFS identity/file/ACL mechanism tests did not run.'
    $script:HostedAssertions+=$ntfsAssertions
    $serviceAssertions=[LumaHostedLifecycleFixture]::RunServiceLifetime()
    Assert-Hosted ($serviceAssertions -ge 18) 'Complete actual threaded service lifecycle software regressions did not run.'
    $script:HostedAssertions+=$serviceAssertions
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),'System.dll','System.Core.dll','System.Security.dll') -Path @((Join-Path $PSScriptRoot 'HostedAuthorityReadFixture.cs'),(Join-Path $PSScriptRoot 'HostedAuthorityEnrollmentFixture.cs'))
    $readAssertions=[LumaHostedReadFixture]::Run([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')),$identity,$timeSigner,$fixtureSigner,$publisherSigner)
    Assert-Hosted ($readAssertions -ge 80) 'Complete actual read-only NTFS/session/wire/persistent-enrollment mechanism regressions did not run.'
    $script:HostedAssertions+=$readAssertions
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),'System.dll','System.Core.dll','System.Security.dll') -Path (Join-Path $PSScriptRoot 'HostedAuthorityIngestionFixture.cs')
    $ingestionAssertions=[LumaHostedIngestionFixture]::Run([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),'System.dll','System.Core.dll','System.Security.dll') -Path (Join-Path $PSScriptRoot 'HostedAuthorityHostProtectionFixture.cs')
    $hostProtectionAssertions=[LumaHostedHostProtectionFixture]::Run()
    Assert-Hosted ($hostProtectionAssertions -ge 180) 'Host protection/provider/cache regression coverage incomplete.'
    $script:HostedAssertions+=$hostProtectionAssertions
    Assert-Hosted ($ingestionAssertions -ge 60) 'Complete scoped-read to fresh independent inference handoff, actual tiny NTFS, cancellation and strict UTF8 software mechanisms did not run.'
    $script:HostedAssertions+=$ingestionAssertions
    $entry=[Luma.Windows.Hosted.JournalEntry]::Prepare($identity,1,[Luma.Windows.Hosted.JournalKind]::Commission,$zero,$zero,$sid,$identity.Encode())
    $entry=$entry.Signed($identity,$keys[2].Sign($entry.SigningInput))
    $decoded=[Luma.Windows.Hosted.JournalEntry]::Decode($identity,$entry.Bytes)
    Assert-Hosted ($decoded.RecordSha256 -ceq $entry.RecordSha256) 'Actual software signature did not verify exact journal bytes.'
    [byte[][]] $records=,$entry.Bytes
    Assert-Hosted ($records.Length -eq 1 -and $records[0].Length -eq $entry.Bytes.Length) 'Fixture flattened an exact journal record.'
    $history=[Luma.Windows.Hosted.JournalHistory]::Replay($identity,$records)
    Assert-Hosted ($history.Sequence -eq 1 -and $history.Head -ceq $entry.NextHead) 'Exact signed journal replay differs.'
    Assert-Hosted ($history.Reconcile($identity,$null,$entry.NextHead).ToString() -ceq 'Clean') 'Clean hardware-head comparison differs.'
    Assert-Hosted ($history.Reconcile($identity,$entry.Bytes,$entry.NextHead).ToString() -ceq 'AlreadyPublished') 'Duplicate published intent was not recognized exactly.'
    $next=[Luma.Windows.Hosted.JournalEntry]::Prepare($identity,2,[Luma.Windows.Hosted.JournalKind]::ImportPrepared,$entry.NextHead,$entry.RecordSha256,$sid,[Text.Encoding]::UTF8.GetBytes('exact reviewed import'))
    $next=$next.Signed($identity,$keys[2].Sign($next.SigningInput))
    Assert-Hosted ($history.Reconcile($identity,$next.Bytes,$entry.NextHead).ToString() -ceq 'PreparedNotExtended') 'Prepared-only crash phase differs.'
    Assert-Hosted ($history.Reconcile($identity,$next.Bytes,$next.NextHead).ToString() -ceq 'ExtendedNotPublished') 'Extended-only crash phase differs.'
    Assert-HostedThrows {$history.Reconcile($identity,$next.Bytes,('12'*32))} 'Damaged NV head was silently repaired.'
    Assert-HostedThrows {$history.Reconcile($identity,$null,$next.NextHead)} 'Rolled-back history was accepted against later NV.'
    Assert-HostedThrows {[Luma.Windows.Hosted.JournalEntry]::Decode($other,$entry.Bytes)} 'Cross-domain or cross-key journal record accepted.'
    Assert-HostedThrows {$entry.Signed($identity,$keys[3].Sign($entry.SigningInput))} 'Wrong actual signing key accepted.'
    Assert-HostedThrows {[Luma.Windows.Hosted.JournalHistory]::Replay($identity,[byte[][]](,$next.Bytes))} 'Journal sequence gap accepted.'
    Assert-HostedThrows {[Luma.Windows.Hosted.JournalHistory]::Replay($identity,[byte[][]]@($entry.Bytes,$entry.Bytes))} 'Journal replay accepted.'
    [byte[]] $changed=$entry.Bytes;$changed[$changed.Length-1]=$changed[$changed.Length-1] -bxor 1
    Assert-HostedThrows {[Luma.Windows.Hosted.JournalEntry]::Decode($identity,$changed)} 'Corrupt actual signature accepted.'
    [byte[]] $copy=$entry.Payload;$copy[0]=$copy[0] -bxor 1
    Assert-Hosted ($entry.RecordSha256 -ceq $decoded.RecordSha256) 'External caller mutated retained journal buffers.'
    foreach ($size in @(0,4097)) {
        Assert-HostedThrows {[Luma.Windows.Hosted.JournalEntry]::Prepare($identity,2,[Luma.Windows.Hosted.JournalKind]::Imported,$entry.NextHead,$entry.RecordSha256,$sid,(New-Object byte[] $size))} 'Journal payload bound bypassed.'
    }
    [byte[]] $public=$identity.AuthorityKey
    [byte[]] $policy=[Luma.Windows.Hosted.TpmWriteProtocol]::Policy($public,$identity.Domain,$identity.Installation)
    Assert-Hosted ($policy.Length -eq 32) 'Fixed NV policy must use SHA256.'
    Assert-Hosted ([Luma.Windows.Hosted.TpmWriteProtocol]::PolicyReference($identity.Domain,$identity.Installation).Length -eq 33) 'PolicySigned reference must have distinct length from cpHash.'
    [byte[]] $nv=[Luma.Windows.Hosted.TpmWriteProtocol]::NvPublic($public,$identity.Domain,$identity.Installation,$true)
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Hex($nv) -ceq [Luma.Windows.PlatformCustodyProtocol]::Encode([Luma.Windows.PlatformCustodyProtocol]::ExpectedNvPublic($identity.Domain,[Luma.Windows.Hosted.Wire]::Hex($policy)))) 'Writer/inspector NV policy and attributes disagree.'
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Hex([Luma.Windows.Hosted.TpmWriteProtocol]::NvName($public,$identity.Domain,$identity.Installation,$true)) -ceq [Luma.Windows.PlatformCustodyProtocol]::ExpectedNvName($identity.Domain,[Luma.Windows.Hosted.Wire]::Hex($policy))) 'Writer/inspector NV Name disagrees.'
    [byte[]] $digest=[Luma.Windows.Hosted.Wire]::Bytes($entry.RecordSha256,32,$true)
    [byte[]] $apply=[Luma.Windows.Hosted.TpmWriteProtocol]::Apply($identity.Domain,0x03000001,$digest)
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Hex($apply).StartsWith('8002000000410000013601804c5701804c57')) 'Writer substituted TPM command, total size or fixed namespace.'
    Assert-HostedThrows {[Luma.Windows.Hosted.TpmWriteProtocol]::Apply('native-admin',0x03000001,$digest)} 'Writer accepted native TPM namespace.'
    Assert-HostedThrows {[Luma.Windows.Hosted.TpmWriteProtocol]::Apply($identity.Domain,0x80000001,$digest)} 'Policy session borrowed a transient key handle.'
    Assert-Hosted (-not [Luma.Windows.Hosted.Wire]::Equal(
        [Luma.Windows.Hosted.TpmWriteProtocol]::ExtendCpHash($public,$identity.Domain,$identity.Installation,$false,$digest),
        [Luma.Windows.Hosted.TpmWriteProtocol]::ExtendCpHash($public,$identity.Domain,$identity.Installation,$true,$digest))) 'Initial/postwritten NV Names do not change exact command binding.'
    $request=[Luma.Windows.Hosted.GuestComputeRequest]::new('capture','{"format":"text","content":"manual bounded source"}')
    Assert-Hosted ($request.Nonce -cmatch '\A[0-9a-f]{64}\z' -and $request.RequestSha256 -cne $request.PayloadSha256) 'Hosted request nonce or complete-request commitment differs.'
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeRequest]::new('shell','{"command":"true"}')} 'Guest request accepted executable selection.'
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeRequest]::new('capture','')} 'Guest request accepted empty source.'
    [byte[]] $result=[Text.Encoding]::UTF8.GetBytes('{"manual_preview":true,"authority_returned":false}')
    $resultHash=[Luma.Windows.Hosted.Wire]::Hash($result)
    $observation=[ordered]@{schema_version=1;profile='luma-windows-hosted-compute-v1';nonce=$request.Nonce;operation=$request.Operation;
        request_sha256=$request.RequestSha256;payload_sha256=$request.PayloadSha256;result_sha256=$resultHash;result_bytes=$result.Length;
        uid=65534;gid=65534;supplementary_groups=@();cap_inheritable='0000000000000000';cap_permitted='0000000000000000';
        cap_effective='0000000000000000';cap_bounding='0000000000000000';cap_ambient='0000000000000000';no_new_privileges=$true;
        apparmor_profile='luma-hosted-compute';cgroup="0::/lumahosted.slice/luma-hosted-compute.service`n";
        memory_max_bytes=536870912;memory_swap_max_bytes=0;tasks_max=1;cpu_quota_usec=100000;cpu_period_usec=100000;runtime_cpu_seconds=30;
        principal_authenticated=$false;grants_admitted=$false;authority_returned=$false;committed=$false;workflow_executed=$false;production_qualified=$false}
    function Encode-HostedObservation {,[Text.Encoding]::UTF8.GetBytes(($observation | ConvertTo-Json -Compress -Depth 4))}
    [byte[]] $metadata=Encode-HostedObservation
    $verified=[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,$metadata)
    Assert-Hosted ($verified.ResultBytes -eq $result.Length -and $verified.ResultSha256 -ceq $resultHash) 'Exact software observation did not preserve its result commitment.'
    foreach ($field in @('authority_returned','principal_authenticated','grants_admitted','committed','workflow_executed','production_qualified')) {
        $observation[$field]=$true
        Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,(Encode-HostedObservation))} ('Guest authority flag accepted: '+$field)
        $observation[$field]=$false
    }
    foreach ($change in @(@('tasks_max',2),@('memory_swap_max_bytes',1),@('uid',0),@('no_new_privileges',$false),@('cap_effective','0000000000000001'),@('result_bytes',16777217))) {
        $field=$change[0];$prior=$observation[$field];$observation[$field]=$change[1]
        Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,(Encode-HostedObservation))} ('Actual confinement substitution accepted: '+$field)
        $observation[$field]=$prior
    }
    $observation.supplementary_groups=@(65534)
    $null=[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,(Encode-HostedObservation))
    Assert-Hosted $true 'Sole primary group representation rejected.'
    $observation.supplementary_groups=@(0)
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,(Encode-HostedObservation))} 'Guest root supplementary group accepted.'
    $observation.supplementary_groups=@()
    $duplicate=[Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString($metadata)).Replace('{','{"schema_version":1,'))
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,$duplicate)} 'Duplicate guest metadata key accepted.'
    $observation.schema_version=$true
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestComputeObservation]::Validate($request,(Encode-HostedObservation))} 'Boolean coerced into metadata integer.'
    $observation.schema_version=1
    $drain=[ordered]@{schema_version=1;profile='luma-windows-hosted-compute-v1';unit='luma-hosted-compute.service';
        cgroup_empty_or_absent=$true;unit_inactive=$true;authority_returned=$false;job_completed=$false}
    [Luma.Windows.Hosted.GuestDrainObservation]::Validate([Text.Encoding]::UTF8.GetBytes(($drain | ConvertTo-Json -Compress)))
    Assert-Hosted $true 'Exact observed drain metadata rejected.'
    $drain.cgroup_empty_or_absent=$false
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestDrainObservation]::Validate([Text.Encoding]::UTF8.GetBytes(($drain | ConvertTo-Json -Compress)))} 'Controller exit inferred guest drain despite occupied cgroup.'
    $drain.cgroup_empty_or_absent=$true;$drain.job_completed=$true
    Assert-HostedThrows {[Luma.Windows.Hosted.GuestDrainObservation]::Validate([Text.Encoding]::UTF8.GetBytes(($drain | ConvertTo-Json -Compress)))} 'Read-only drain fabricated successful compute execution.'
    Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),'System.dll','System.Core.dll') -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using Luma.Windows.Hosted;
public static class LumaHostedFrameFixture {
    public static byte[] Exchange(GuestComputeRequest request,byte[] metadata,byte[] result,int mode) {
        using(MemoryStream source=new MemoryStream()) using(MemoryStream output=new MemoryStream()) {
            byte[] magic=Encoding.ASCII.GetBytes("LUMAWINCOMPv1!!\n");source.Write(magic,0,magic.Length);
            byte[] length=GuestComputeFrames.Length((uint)metadata.Length);source.Write(length,0,4);source.Write(metadata,0,metadata.Length);
            if(mode==2) result=(byte[])result.Clone();if(mode==2) result[0]^=1;
            source.Write(result,0,result.Length);if(mode==3) source.WriteByte(0);source.Position=0;
            byte[] actual=GuestComputeFrames.Exchange(request,source,output,delegate {if(mode==1) throw new System.Security.SecurityException("Actual fixture cancellation.");});
            byte[] written=output.ToArray();if(written.Length!=4+request.Bytes.Length+40) throw new Exception("Exact ACK count differs.");
            byte[] hash=Wire.HashBytes(actual);int at=written.Length-40;ulong acknowledged=0;
            for(int index=0;index<8;index++) acknowledged=(acknowledged<<8)|written[at+index];
            if(acknowledged!=(ulong)actual.Length) throw new Exception("Cumulative byte ACK differs.");
            for(int index=0;index<32;index++) if(written[at+8+index]!=hash[index]) throw new Exception("Cumulative hash ACK differs.");return actual;
        }
    }
}
'@
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Hash([LumaHostedFrameFixture]::Exchange($request,$metadata,$result,0)) -ceq $resultHash) 'Actual bounded frame parser or byte/hash acknowledgement differs.'
    foreach ($mode in @(1,2,3)) {Assert-HostedThrows {[LumaHostedFrameFixture]::Exchange($request,$metadata,$result,$mode)} ('Cancelled, changed or trailing frame accepted: '+$mode)}
    $intent=[Luma.Windows.Hosted.CommissionIntent]::new($identity.Domain,$identity.Installation,$sid,'lab',$identity.ReleaseKey,$identity.TimeKey,
        $identity.ServiceSha256,$identity.WslSha256,'https://time.example.invalid/luma/challenge',[LumaHostedLifecycleFixture]::SoftwareBaseline($identity))
    $decodedIntent=[Luma.Windows.Hosted.CommissionIntent]::Decode($intent.Encode())
    Assert-Hosted ($decodedIntent.TimeEndpoint -ceq $intent.TimeEndpoint -and [Luma.Windows.Hosted.Wire]::Equal($decodedIntent.Encode(),$intent.Encode())) 'Closed commissioning intent did not bind the exact fixed UTC endpoint.'
    foreach ($endpoint in @('http://time.example.invalid/challenge','https://user:secret@time.example.invalid/challenge',
            'https://time.example.invalid/challenge#key','https://time.example.invalid/challenge?key=secret','file:///C:/Windows/system.ini')) {
        Assert-HostedThrows {[Luma.Windows.Hosted.HostedTimeEndpoint]::Validate($endpoint)} 'UTC commissioning accepted insecure, credential-bearing, query, fragment or local-file source.'
    }
    $files=[Collections.Generic.List[Luma.Windows.RequiredFile]]::new()
    foreach ($name in @('etc/os-release','etc/wsl.conf','usr/bin/luma-platform','usr/lib/luma/platform.json')) {
        $file=[Luma.Windows.RequiredFile]::new();$file.Path=$name;$file.Bytes=1;$file.Sha256='12'*32;$file.Executable=$false
        if ($name -ceq 'usr/bin/luma-platform') {$file.Bytes=64;$file.Executable=$true}
        $files.Add($file)
    }
    $release=[Luma.Windows.Hosted.ReleaseDescriptor]::new('lab',1,1000000,2000000,('0'*64),('34'*32),('56'*32),1024,67,8,$files.ToArray())
    $null=$release.Verify($identity,$keys[0].Sign($release.SigningInput()))
    Assert-Hosted $true 'Independent actual release signature refused.'
    Assert-HostedThrows {$release.Verify($identity,$keys[1].Sign($release.SigningInput()))} 'UTC authority was allowed to sign a deployment release.'
    $decodedRelease=[Luma.Windows.Hosted.ReleaseDescriptor]::Decode($release.Encode())
    Assert-Hosted ([Luma.Windows.Hosted.Wire]::Equal($decodedRelease.Encode(),$release.Encode())) 'Exact closed signed release codec roundtrip differs.'
    $flags=[Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
    $liveType=[Luma.Windows.Hosted.AuthorityIdentity].Assembly.GetType('Luma.Windows.Hosted.LiveRelease',$true)
    function New-ActualLiveRelease {,[Activator]::CreateInstance($liveType,$flags,$null,[object[]]@($identity,$release),$null)}
    function Accept-ActualTime($live,[uint64]$lower,[uint64]$upper,$signingKey) {
        $nonce=$liveType.GetProperty('Nonce',$flags).GetValue($live,$null)
        $proof=[Luma.Windows.Hosted.TimeAttestation]::new($identity.Installation,$nonce,[Luma.Windows.Hosted.Wire]::Hash($release.Encode()),$lower,$upper)
        $invoke=[object[]]::new(2);$invoke[0]=$proof.Encode();$invoke[1]=$signingKey.Sign($proof.Encode())
        $null=$liveType.GetMethod('Accept',$flags).Invoke($live,$invoke)
    }
    $live=New-ActualLiveRelease
    Accept-ActualTime $live 1000001 1000010 $keys[1]
    Assert-Hosted $true 'Actual nonce-signed independent UTC software verification failed.'
    Assert-HostedThrows {Accept-ActualTime $live 1000001 1000010 $keys[1]} 'UTC nonce/session accepted a second delivery.'
    Assert-HostedThrows {Accept-ActualTime (New-ActualLiveRelease) 1000001 1000010 $keys[0]} 'Release authority was allowed to deliver protected UTC.'
    Assert-HostedThrows {Accept-ActualTime (New-ActualLiveRelease) 1999995 2000000 $keys[1]} 'Half-open release expiry accepted an interval touching expiry.'
    $delayed=New-ActualLiveRelease
    [Threading.Thread]::Sleep(100)
    Assert-HostedThrows {Accept-ActualTime $delayed 1999940 1999950 $keys[1]} 'Protected UTC omitted actual nonce-to-receipt network/issuance delay from its upper bound.'
    $script:UtcOriginalChecks=0;$script:UtcPreviousChecks=0
    Assert-Hosted (-not [Luma.Windows.Hosted.HostedUtcContinuation]::RenewalDue([TimeSpan]::FromTicks(99999999))) 'Protected UTC refreshed before its exact ten-second whole-nonce threshold.'
    Assert-Hosted ([Luma.Windows.Hosted.HostedUtcContinuation]::RenewalDue([TimeSpan]::FromSeconds(10))) 'Protected UTC renewal omitted time spent obtaining the previous proof.'
    Assert-HostedThrows {[Luma.Windows.Hosted.HostedUtcContinuation]::RenewalDue([TimeSpan]::FromTicks(-1))} 'Negative whole UTC nonce age accepted.'
    $initialContinuation=[Luma.Windows.Hosted.HostedUtcContinuation]::Require([Action]{$script:UtcOriginalChecks++},[Action]$null)
    $initialContinuation.Invoke()
    Assert-Hosted ($script:UtcOriginalChecks -eq 2) 'First UTC proof did not keep original caller checks around relay continuation.'
    $prior=New-ActualLiveRelease
    Accept-ActualTime $prior 1999500 1999510 $keys[1]
    $priorCheck=[Action]{$script:UtcPreviousChecks++;$null=$liveType.GetMethod('Check',$flags).Invoke($prior,$null)}
    $continuation=[Luma.Windows.Hosted.HostedUtcContinuation]::Require([Action]{$script:UtcOriginalChecks++},$priorCheck)
    $continuation.Invoke()
    Assert-Hosted ($script:UtcPreviousChecks -eq 1) 'Renewal omitted the exact previously accepted independent proof.'
    [Threading.Thread]::Sleep(600)
    Assert-HostedThrows {$continuation.Invoke()} 'Slow UTC renewal crossed the previously accepted release interval while allowing continued work.'
    $fresh=New-ActualLiveRelease;Accept-ActualTime $fresh 1000001 1000010 $keys[1]
    Assert-HostedThrows {$continuation.Invoke()} 'A separately fresh proof retroactively bridged an expired previous UTC continuation.'
    $script:UtcPriorAfterExpiry=0
    $expiredOriginal=[Luma.Windows.Hosted.HostedUtcContinuation]::Require([Action]{throw [Security.SecurityException]::new('Actual original caller expired.')},[Action]{$script:UtcPriorAfterExpiry++})
    Assert-HostedThrows {$expiredOriginal.Invoke()} 'UTC renewal ignored original caller expiry.'
    Assert-Hosted ($script:UtcPriorAfterExpiry -eq 0) 'Expired original caller continued into another proof ceremony.'
    $forged=[Luma.Windows.PackageContent]::new()
    Assert-HostedThrows {[Luma.Windows.PackageInspector]::ValidateHostedProfile($forged,$files.ToArray())} 'Caller-constructed package metadata was accepted as genuine inspection.'
    $script:PackageCallbackCount=0
    Assert-HostedThrows {[Luma.Windows.PackageInspector]::Validate('Z:\luma-nonexistent-authority-fixture.tar',1024,67,8,('56'*32),$files.ToArray(),[Action]{
        $script:PackageCallbackCount++;throw [Security.SecurityException]::new('Actual live-boundary refusal before any archive open.')
    })} 'Checked archive inspection bypassed a live pre-open refusal.'
    Assert-Hosted ($script:PackageCallbackCount -eq 1) 'Checked archive inspection did not call its live boundary before opening input.'
    Assert-HostedThrows {[Luma.Windows.PackageInspector]::Validate('Z:\luma-nonexistent-authority-fixture.tar',1024,67,8,('56'*32),$files.ToArray(),[Action]$null)} 'Authority archive inspection accepted an absent continuous boundary.'
    $inferenceCasesHash=$null
    if ($InferenceCasesPath) {
        if ($InferenceCasesPath -notmatch '\A[A-Za-z]:\\' -or $InferenceCasesPath.Contains('/') -or $InferenceCasesPath -match '(^|\\)\.{1,2}(\\|$)' -or $InferenceCasesPath.Substring(2).Contains(':')) {throw 'Inference test-case export requires one exact canonical local new-file path.'}
        $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($InferenceCasesPath)) -Force
        if ($parent -isnot [IO.DirectoryInfo]) {throw 'Inference test-case parent must exist.'}
        for ($ancestor=$parent;$null -ne $ancestor;$ancestor=$ancestor.Parent) {if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Inference test-case output may not traverse reparse points.'}}
        $cases=@(foreach ($wire in [LumaHostedInferenceFixture]::Requests()) {
            $requestCase=[Luma.Windows.Hosted.GuestInferenceRequest]::Decode($wire)
            [ordered]@{request_base64=[Convert]::ToBase64String($wire);request_sha256=$requestCase.RequestSha256;prompt_sha256=$requestCase.PromptSha256;prompt_bytes=$requestCase.PromptBytes;max_tokens=$requestCase.MaximumTokens}
        })
        $caseBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(([ordered]@{schema_version=1;kind='actual-csharp-inference-wire-fixtures';cases=$cases;authority_returned=$false;inference_executed=$false;production_qualified=$false} | ConvertTo-Json -Depth 6 -Compress))
        $stream=[IO.FileStream]::new($InferenceCasesPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$stream.Write($caseBytes,0,$caseBytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
        $inferenceCasesHash=(Get-FileHash -LiteralPath $InferenceCasesPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [pscustomobject][ordered]@{schema_version=1;status='hosted-software-protocol-tests-passed';assertions=$script:HostedAssertions;
        build_directory=$build.work_directory;actual_ephemeral_bcrypt_signatures=$true;hardware_custody_invoked=$false;
        live_service_installed=$false;host_tpm_mutated=$false;distribution_imported=$false;actual_current_user_ntfs_identity_lease_fixture=$true;actual_threaded_service_lifecycle_software_tests=$true;
        installed_scm_stop_qualified=$false;installed_system_acl_qualified=$false;ntfs_durability_qualified=$false;
        actual_read_only_ntfs_and_wire_mechanism_tests=$true;signed_persistent_enrollment_software_tests=$true;installed_authenticated_read_bridge_qualified=$false;installed_persistent_enrollment_qualified=$false;linux_principal_mapping=$false;
        signed_compute_lifecycle_and_delivery_tests=$true;held_original_compute_input_ntfs_tests=$true;compute_assertions=$computeAssertions;actual_guest_compute_executed=$false;model_inference_executed=$false;
        signed_inference_lifecycle_and_delivery_tests=$true;inference_assertions=$inferenceAssertions;actual_guest_inference_executed=$false;five_minute_purpose_approved=$true;compute_purpose_seconds=30;inference_purpose_seconds=300;
        inference_mechanism_assertions=$inferenceMechanismAssertions;held_original_inference_input_ntfs_tests=$true;closed_inference_profile_runtime_join_tests=$true;
        ingestion_assertions=$ingestionAssertions;scoped_read_to_fresh_inference_handoff_tests=$true;actual_authenticated_ingestion_to_model_qualified=$false;
        host_protection_assertions=$hostProtectionAssertions;read_only_host_protection_contracts=$true;actual_encryption_state_modified=$false;enterprise_authorization_created=$false;
        inference_wire_cases_path=$InferenceCasesPath;inference_wire_cases_sha256=$inferenceCasesHash;
        production_qualified=$false;gate_closing=$false} | ConvertTo-Json -Depth 8
} finally {
    foreach ($key in $keys) {if ($null -ne $key) {$key.Dispose()}}
    $env:TEMP=$priorTemp;$env:TMP=$priorTmp
}
