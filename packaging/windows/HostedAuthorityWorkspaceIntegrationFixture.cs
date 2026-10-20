using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security;
using System.Text;
using Luma.Windows.Hosted;

// Genuine software-signed histories and production codecs/controllers' closed
// selections. Never starts WSL, a console, a service or an installed account.
public static class LumaHostedWorkspaceIntegrationFixture
{
    private static int assertions;private static string H(char value) {return new string(value,64);}
    private static byte[] B(string value) {return Encoding.ASCII.GetBytes(value);}
    private static void Require(bool value) {if(!value) throw new Exception("Workspace integrated lifecycle assertion failed.");assertions++;}
    private static void Refuse(Action action) {try {action();}catch(SecurityException){assertions++;return;}catch(InvalidDataException){assertions++;return;}catch(EndOfStreamException){assertions++;return;}throw new Exception("Workspace lifecycle accepted an invalid transition.");}
    private static object Call(Type type,object target,string name,params object[] args) {try{return type.GetMethod(name,BindingFlags.Static|BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic).Invoke(target,args);}catch(TargetInvocationException error){throw error.InnerException;}}
    private static object New(Type type,params object[] args) {try{return Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,args,null);}catch(TargetInvocationException error){throw error.InnerException;}}
    private static Type Internal(string name) {return typeof(GuestWorkspaceRequest).Assembly.GetType("Luma.Windows.Hosted."+name,true);}
    private static DeploymentEvent Event(byte purpose,string generation,uint pid,byte outcome,string digest) {return new DeploymentEvent(purpose,H('1'),1,generation,123,"ticket-package-"+new string('b',32)+".tar",pid,pid==0?0UL:456UL,outcome,digest);}
    private static JournalEntry Candidate(AuthorityIdentity identity,Func<byte[],byte[]> sign,JournalHistory history,JournalKind kind,byte[] payload) {JournalEntry value=JournalEntry.Prepare(identity,history.Sequence+1,kind,history.Head,history.Record,identity.FirstAdminSid,payload);return value.Signed(identity,sign(value.SigningInput));}
    private static JournalHistory Add(AuthorityIdentity identity,Func<byte[],byte[]> sign,JournalHistory history,JournalKind kind,byte[] payload) {
        List<byte[]> records=new List<byte[]>();foreach(JournalEntry value in history.Entries)records.Add(value.Bytes);records.Add(Candidate(identity,sign,history,kind,payload).Bytes);return JournalHistory.Replay(identity,records.ToArray());
    }
    private static JournalHistory Base(AuthorityIdentity identity,Func<byte[],byte[]> sign,CommissionIntent intent) {
        JournalEntry genesis=JournalEntry.Prepare(identity,1,JournalKind.Commission,H('0'),H('0'),identity.FirstAdminSid,intent.GenesisPayload(identity));genesis=genesis.Signed(identity,sign(genesis.SigningInput));JournalHistory history=JournalHistory.Replay(identity,new byte[][]{genesis.Bytes});
        foreach(byte purpose in new byte[]{1,2}) {string gen=purpose==1?H('a'):H('b');history=Add(identity,sign,history,purpose==1?JournalKind.ImportPrepared:JournalKind.ActivationPrepared,Event(purpose,gen,0,0,H('0')).Encode());history=Add(identity,sign,history,JournalKind.ControllerStarted,Event(purpose,gen,44,0,H('0')).Encode());history=Add(identity,sign,history,JournalKind.ControllerCompleted,Event(purpose,gen,44,1,H('c')).Encode());history=Add(identity,sign,history,purpose==1?JournalKind.Imported:JournalKind.Activated,Event(purpose,gen,0,1,H('c')).Encode());}return history;
    }
    private static HostedWorkspacePreparation Prepare(AuthorityIdentity identity,Func<byte[],byte[]> time,byte operation,GuestWorkspaceRequest original,uint day,string login) {
        byte[] proof=new TimeAttestation(identity.Installation,H('8'),H('1'),(ulong)day*86400000+1000,(ulong)day*86400000+1001).Encode();
        GuestWorkspaceRequest request=new GuestWorkspaceRequest(identity.Installation,H('1'),H('3'),Wire.Hash(GuestWorkspaceRequest.ExpectedProfile(H('3'))),Wire.Hash(B(identity.FirstAdminSid)),login,day,Wire.Hash(proof));
        return new HostedWorkspacePreparation(Event(5,request.RequestSha256,0,0,H('0')),request,original??request,operation,proof,time(proof));
    }
    private static JournalHistory Finish(AuthorityIdentity identity,Func<byte[],byte[]> sign,JournalHistory prepared,HostedWorkspacePreparation intent,byte[] metadata) {
        string digest=intent.Operation==2?Wire.Hash(metadata):H('d');string generation=intent.Admission.Generation;
        JournalHistory history=Add(identity,sign,prepared,JournalKind.ControllerStarted,Event(5,generation,55,0,generation).Encode());history=Add(identity,sign,history,JournalKind.ControllerCompleted,Event(5,generation,55,1,digest).Encode());return Add(identity,sign,history,JournalKind.WorkspaceObserved,new HostedWorkspaceCompletion(Event(5,generation,0,1,digest),intent.Operation,metadata).Encode());
    }
    private static byte[] Metadata(HostedWorkspacePreparation prepared,string witness,bool complete,bool pam) {
        GuestWorkspaceRequest request=prepared.Request;
        return B("{\"schema_version\":1,\"profile\":\""+GuestWorkspaceRequest.Profile+"\",\"nonce\":\""+request.Nonce+"\",\"request_sha256\":\""+request.RequestSha256+"\",\"installation\":\""+request.Installation+"\",\"release_sha256\":\""+request.ReleaseSha256+"\",\"runtime_manifest_sha256\":\""+request.RuntimeManifestSha256+"\",\"profile_sha256\":\""+request.ProfileSha256+"\",\"actor_sid_sha256\":\""+request.ActorSidSha256+"\",\"account_generation\":1,\"uid\":1000,\"bootstrap_request_sha256\":\""+prepared.Original.RequestSha256+"\",\"protected_utc_day\":"+request.ProtectedUtcDay+",\"utc_proof_sha256\":\""+request.UtcProofSha256+"\",\"password_age_within_90_days\":"+(request.WithinPasswordAge(prepared.Original)?"true":"false")+",\"applied_file_count\":"+(complete?4:0)+",\"account_files_complete\":"+(complete?"true":"false")+",\"bootstrap_pam_verified_once\":"+(pam?"true":"false")+",\"account_state_sha256\":\""+witness+"\",\"native_product_grant_bridge_available\":false,\"inference_observation\":\"not-requested\",\"authority_returned\":false,\"production_qualified\":false}");
    }
    public static int Run(AuthorityIdentity identity,Func<byte[],byte[]> sign,Func<byte[],byte[]> time,RuntimeBundle baseline) {
        assertions=0;CommissionIntent commission=new CommissionIntent(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,identity.ReleaseKey,identity.TimeKey,identity.ServiceSha256,identity.WslSha256,"https://time.example.invalid/luma/challenge",baseline);
        JournalHistory initial=Base(identity,sign,commission);Require(DeploymentHistory.Replay(initial).Active!=null);
        HostedWorkspacePreparation setup=Prepare(identity,time,1,null,20746,"alice");Require(setup.Encode().Length<4096);Require(Wire.Equal(HostedWorkspacePreparation.Decode(setup.Encode()).Encode(),setup.Encode()));setup.RequireIdentity(identity,identity.FirstAdminSid);assertions++;
        Refuse(delegate {setup.RequireIdentity(identity,"S-1-5-18");});
        foreach(byte purpose in new byte[]{1,2,3,4}) Refuse(delegate {new HostedWorkspacePreparation(Event(purpose,setup.Request.RequestSha256,0,0,H('0')),setup.Request,setup.Original,1,new TimeAttestation(identity.Installation,H('8'),H('1'),20746UL*86400000+1000,20746UL*86400000+1001).Encode(),new byte[64]);});
        JournalEntry proposed=Candidate(identity,sign,initial,JournalKind.WorkspacePrepared,setup.Encode());int staged=0;DeploymentHistory.ValidateNext(identity,initial,proposed,delegate {},commission);staged++;Require(staged==1);
        Refuse(delegate {DeploymentHistory.ValidateNext(identity,initial,proposed,delegate {});});
        byte[] invalid=setup.Encode();invalid[invalid.Length-1]^=1;JournalEntry badSignature=Candidate(identity,sign,initial,JournalKind.WorkspacePrepared,invalid);staged=0;Refuse(delegate {DeploymentHistory.ValidateNext(identity,initial,badSignature,delegate {},commission);staged++;});Require(staged==0);
        JournalHistory prepared=Add(identity,sign,initial,JournalKind.WorkspacePrepared,setup.Encode());DeploymentHistory pending=DeploymentHistory.Replay(prepared);Require(pending.Pending.Purpose==5 && pending.Workspace(H('1'))!=null && !pending.Workspace(H('1')).ConsoleCompleted);Require(pending.DrainRequestSha256()==setup.Request.RequestSha256);
        HostedTrustState.Replay(identity,commission,prepared,delegate {}).ForCleanup(setup.Admission.Generation);assertions++;
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,prepared,JournalKind.WorkspacePrepared,setup.Encode()));});
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,initial,JournalKind.ComputePrepared,setup.Admission.Encode()));});
        JournalHistory noStart=Add(identity,sign,prepared,JournalKind.Cancelled,Event(5,setup.Admission.Generation,0,2,H('e')).Encode());Require(DeploymentHistory.Replay(noStart).Workspace(H('1'))==null);
        JournalHistory running=Add(identity,sign,prepared,JournalKind.ControllerStarted,Event(5,setup.Admission.Generation,55,0,setup.Admission.Generation).Encode());Require(DeploymentHistory.Replay(running).DrainRequestSha256()==setup.Request.RequestSha256);
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,running,JournalKind.Cancelled,Event(5,setup.Admission.Generation,0,2,H('e')).Encode()));});
        JournalHistory failure=Add(identity,sign,running,JournalKind.ControllerCompleted,Event(5,setup.Admission.Generation,55,2,H('e')).Encode());JournalHistory abandoned=Add(identity,sign,failure,JournalKind.Cancelled,Event(5,setup.Admission.Generation,0,2,H('e')).Encode());Require(DeploymentHistory.Replay(abandoned).Workspace(H('1')).Original.RequestSha256==setup.Request.RequestSha256);
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,abandoned,JournalKind.WorkspacePrepared,Prepare(identity,time,1,null,20746,"bob").Encode()));});
        HostedWorkspacePreparation repair=Prepare(identity,time,3,setup.Original,20747,"alice");JournalHistory repaired=Finish(identity,sign,Add(identity,sign,abandoned,JournalKind.WorkspacePrepared,repair.Encode()),repair,new byte[0]);Require(DeploymentHistory.Replay(repaired).Workspace(H('1')).ConsoleCompleted && !DeploymentHistory.Replay(repaired).Workspace(H('1')).ManualHealthReady);
        JournalHistory console=Finish(identity,sign,prepared,setup,new byte[0]);Require(DeploymentHistory.Replay(console).Pending==null && DeploymentHistory.Replay(console).Workspace(H('1')).ConsoleCompleted && !DeploymentHistory.Replay(console).Workspace(H('1')).ManualHealthReady);
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,console,JournalKind.WorkspacePrepared,setup.Encode()));});
        HostedWorkspacePreparation health=Prepare(identity,time,2,setup.Original,20747,"alice");JournalHistory healthPrepared=Add(identity,sign,console,JournalKind.WorkspacePrepared,health.Encode());byte[] metadata=Metadata(health,H('a'),true,true);
        JournalHistory healthy=Finish(identity,sign,healthPrepared,health,metadata);Require(DeploymentHistory.Replay(healthy).Workspace(H('1')).ManualHealthReady);Require(HostedTrustState.Replay(identity,commission,healthy,delegate {}).CurrentIdentity.Installation==identity.Installation);
        HostedWorkspacePreparation fresh=Prepare(identity,time,2,setup.Original,20748,"alice");JournalHistory freshPrepared=Add(identity,sign,healthy,JournalKind.WorkspacePrepared,fresh.Encode());JournalHistory freshHealthy=Finish(identity,sign,freshPrepared,fresh,Metadata(fresh,H('a'),true,true));Require(DeploymentHistory.Replay(freshHealthy).Workspace(H('1')).ManualHealthReady);
        Require(DeploymentHistory.Replay(freshHealthy).Workspace(H('1')).LastProtectedUtcDay==20748);
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,freshHealthy,JournalKind.WorkspacePrepared,Prepare(identity,time,2,setup.Original,20747,"alice").Encode()));});
        JournalHistory abandonedHealth=Add(identity,sign,freshPrepared,JournalKind.Cancelled,Event(5,fresh.Admission.Generation,0,2,H('e')).Encode());
        Refuse(delegate {DeploymentHistory.Replay(Add(identity,sign,abandonedHealth,JournalKind.WorkspacePrepared,Prepare(identity,time,2,setup.Original,20747,"alice").Encode()));});
        Refuse(delegate {DeploymentHistory.Replay(Finish(identity,sign,freshPrepared,fresh,Metadata(fresh,H('b'),true,true)));});
        Refuse(delegate {new HostedWorkspaceCompletion(Event(5,health.Admission.Generation,0,1,H('d')),2,metadata);});
        foreach(byte operation in new byte[]{0,4,255}) Refuse(delegate {new HostedWorkspaceCompletion(Event(5,health.Admission.Generation,0,1,H('d')),operation,new byte[0]);});
        HostedWorkspacePreparation expired=Prepare(identity,time,2,setup.Original,20836,"alice");Require(!DeploymentHistory.Replay(Finish(identity,sign,Add(identity,sign,healthy,JournalKind.WorkspacePrepared,expired.Encode()),expired,Metadata(expired,H('a'),true,true))).Workspace(H('1')).ManualHealthReady);
        Refuse(delegate {Prepare(identity,time,2,setup.Original,20747,"bob");});Refuse(delegate {Prepare(identity,time,3,setup.Original,20745,"alice");});
        using(Wire.Writer review=new Wire.Writer("luma-windows-hosted-workspace-review-v1")) {review.Blob(health.Encode(),4096);review.Fixed(Wire.Bytes(healthy.Head,32,true),32);byte[] bytes=review.Bytes();Require(HostedWorkspaceReview.Validate(bytes,2,H('1'),"alice",health.Request.Nonce,identity.FirstAdminSid).Request.RequestSha256==health.Request.RequestSha256);
            Refuse(delegate {HostedWorkspaceReview.Validate(bytes,1,H('1'),"alice",health.Request.Nonce,identity.FirstAdminSid);});Refuse(delegate {HostedWorkspaceReview.Validate(bytes,2,H('2'),"alice",health.Request.Nonce,identity.FirstAdminSid);});Refuse(delegate {HostedWorkspaceReview.Validate(bytes,2,H('1'),"bob",health.Request.Nonce,identity.FirstAdminSid);});Refuse(delegate {HostedWorkspaceReview.Validate(bytes,2,H('1'),"alice",H('9'),identity.FirstAdminSid);});Refuse(delegate {HostedWorkspaceReview.Validate(bytes,2,H('1'),"alice",health.Request.Nonce,"S-1-5-18");});}
        Type invocation=Internal("HostedWorkspaceInvocation");foreach(HostedWorkspacePreparation selection in new HostedWorkspacePreparation[]{setup,health,repair}) {
            object actual=New(invocation,identity,selection);string[] args=(string[])invocation.GetProperty("Arguments",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(actual,null);Require(args.Length==12 && args[7]==selection.Admission.Generation && args[8]==selection.Request.RequestSha256 && args[9]==setup.Original.RequestSha256 && args[10]==selection.Request.PublicHex && args[11]==selection.Original.PublicHex);
            Require((bool)invocation.GetField("Interactive",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(actual)==(selection.Operation!=2));Call(invocation,actual,"RequireArguments",(object)args);assertions++;
            for(int index=0;index<args.Length;index++){string[] changed=(string[])args.Clone();changed[index]+="x";Refuse(delegate {Call(invocation,actual,"RequireArguments",(object)changed);});}
            string[] copy=(string[])invocation.GetProperty("Arguments",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(actual,null);args[10]="changed";Require(copy[10]==selection.Request.PublicHex);
        }
        Refuse(delegate {Call(Internal("OwnedWindowsProcess"),null,"Argument",new string('a',1025));});
        object drainage=Call(invocation,null,"Drain",identity,setup.Admission,setup.Request.RequestSha256);string[] drainArgs=(string[])invocation.GetProperty("Arguments",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(drainage,null);Require(drainArgs.Length==8 && drainArgs[6]=="hosted-windows-workspace-drain" && drainArgs[7]==setup.Request.RequestSha256);
        string drain="{\"schema_version\":1,\"profile\":\""+GuestWorkspaceRequest.Profile+"\",\"unit\":\"luma-hosted-workspace-bootstrap.service\",\"cgroup_empty_or_absent\":true,\"unit_inactive\":true,\"authority_returned\":false,\"job_completed\":false}";Call(Internal("HostedWorkspaceRunner"),null,"ValidateDrain",B(drain));assertions++;
        foreach(string wrong in new string[]{drain.Replace("\"job_completed\":false","\"job_completed\":true"),drain.Replace("\"authority_returned\":false","\"authority_returned\":true"),drain.Replace("workspace-bootstrap.service","compute.service"),drain.Replace("\"unit_inactive\":true","\"unit_inactive\":1"),drain+"{}"}) Refuse(delegate {Call(Internal("HostedWorkspaceRunner"),null,"ValidateDrain",B(wrong));});
        byte[] utcProof=new TimeAttestation(identity.Installation,H('8'),H('1'),20746UL*86400000+1,20746UL*86400000+2).Encode();object snapshot=New(Internal("HostedWorkspaceTime"),utcProof,time(utcProof),20746UL*86400000+3);Require((uint)Internal("HostedWorkspaceTime").GetField("Day",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(snapshot)==20746);
        Refuse(delegate {New(Internal("HostedWorkspaceTime"),utcProof,time(utcProof),20747UL*86400000);});Refuse(delegate {New(Internal("HostedWorkspaceTime"),utcProof,time(utcProof),20746UL*86400000);});
        return assertions;
    }
}
