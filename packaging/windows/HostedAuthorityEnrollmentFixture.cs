// Test-only signed-history and disposable NTFS fixtures, never installed.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Security.Principal;
using Luma.Windows.Hosted;

public static class LumaHostedEnrollmentFixture
{
    private static readonly string Zero=new string('0',64);
    private static void Require(bool value) {if(!value) throw new Exception("Persistent enrollment software fixture failed.");}
    private static void Refuse(Action action) {try {action();}catch(SecurityException) {return;}catch(InvalidDataException) {return;}throw new Exception("Required persistent enrollment refusal did not occur.");}
    private static string H(char value) {return new string(value,64);}
    private static object Call(object value,string method,params object[] arguments) {try {return value.GetType().GetMethod(method,BindingFlags.Instance|BindingFlags.NonPublic).Invoke(value,arguments);}catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}}
    private static object New(string type,params object[] arguments) {try {return Activator.CreateInstance(typeof(EnrolledReadIntent).Assembly.GetType("Luma.Windows.Hosted."+type,true),BindingFlags.Instance|BindingFlags.NonPublic,null,arguments,null);}catch(TargetInvocationException error) {ExceptionDispatchInfo.Capture(error.InnerException??error).Throw();throw;}}
    private static JournalEntry Sign(AuthorityIdentity identity,Func<byte[],byte[]> signer,List<byte[]> history,JournalKind kind,byte[] payload) {
        JournalEntry previous=history.Count==0?null:JournalEntry.Decode(identity,history[history.Count-1]);JournalEntry result=JournalEntry.Prepare(identity,(ulong)history.Count+1,kind,previous==null?Zero:previous.NextHead,previous==null?Zero:previous.RecordSha256,identity.FirstAdminSid,payload);return result.Signed(identity,signer(result.SigningInput));
    }
    private static FileEnrollmentRecord Record(AuthorityIdentity identity,FileEnrollmentIntent intent,byte[] snapshot,Func<byte[],byte[]> time) {
        ulong lower=intent.Action==FileEnrollmentAction.Revoke?2000:intent.NotBefore+10;TimeAttestation proof=new TimeAttestation(identity.Installation,Wire.Hex(Wire.Random(32)),Wire.Hash(intent.Encode()),lower,lower+1);
        return new FileEnrollmentRecord(intent,H('a'),snapshot,proof.Encode(),time(proof.Encode()));
    }
    private static JournalEntry Event(AuthorityIdentity identity,Func<byte[],byte[]> authority,Func<byte[],byte[]> time,List<byte[]> history,FileEnrollmentIntent intent,byte[] snapshot) {return Sign(identity,authority,history,intent.Action==FileEnrollmentAction.Revoke?JournalKind.FileEnrollmentRevoked:JournalKind.FileEnrolled,Record(identity,intent,snapshot,time).Encode());}
    private static FileEnrollmentIntent Proposal(EnrolledReadIntent read,FileEnrollmentAction action,string id,ulong generation,string prior,string registry,string head,ulong start,ulong end) {return new FileEnrollmentIntent(action,id,generation,prior,registry,head,start,end,read);}
    private static JournalHistory History(AuthorityIdentity identity,List<byte[]> records) {return JournalHistory.Replay(identity,records.ToArray(),delegate {});}
    private static List<byte[]> With(List<byte[]> records,JournalEntry next) {List<byte[]> result=new List<byte[]>(records);result.Add(next.Bytes);return result;}
    private static JournalEntry AbortReplacement(AuthorityIdentity identity,Func<byte[],byte[]> sign,List<byte[]> history,JournalEntry abandoned) {
        byte[] input=DispatchTicket.SigningInput(identity,abandoned,1,new TpmEpoch(1,1,1,1,true));
        DispatchTicket ticket=DispatchTicket.Signed(identity,input,sign(input));
        NvAbortEvent abort=new NvAbortEvent(ticket,2,new TpmEpoch(2,2,2,1,true),Wire.Random(32));
        return Sign(identity,sign,history,JournalKind.NvWriteAborted,abort.Encode());
    }
    private static int Capacity(AuthorityIdentity identity,Func<byte[],byte[]> sign,Func<byte[],byte[]> time,
        CommissionIntent commission,EnrolledReadIntent read,byte[] snapshot,int count) {
        int assertions=0;List<byte[]> records=new List<byte[]>();records.Add(Sign(identity,sign,records,JournalKind.Commission,commission.GenesisPayload(identity)).Bytes);
        JournalHistory genesis=History(identity,records);string registry=genesis.FileEnrollments.SourceSha256,head=genesis.Head;
        Dictionary<string,JournalEntry> controls=new Dictionary<string,JournalEntry>();Dictionary<string,ulong> generations=new Dictionary<string,ulong>();
        for(int index=1;index<=count;index++) {
            string id=index.ToString("x64");FileEnrollmentIntent intent=Proposal(read,FileEnrollmentAction.Create,id,1,Zero,registry,head,1000,1000000);
            JournalEntry item=Event(identity,sign,time,records,intent,snapshot);records.Add(item.Bytes);controls[id]=item;generations[id]=1;registry=item.RecordSha256;head=item.NextHead;
        }
        int limit=1024-2*count;
        if((limit-records.Count)%2!=0) {
            string id=1.ToString("x64");FileEnrollmentIntent change=Proposal(read,FileEnrollmentAction.Supersede,id,2,controls[id].RecordSha256,registry,head,1000,1000001);
            JournalEntry item=Event(identity,sign,time,records,change,snapshot);records.Add(item.Bytes);controls[id]=item;generations[id]=2;registry=item.RecordSha256;head=item.NextHead;
        }
        for(int index=0;records.Count<limit;index++) {
            DeploymentEvent value=new DeploymentEvent(1,H('7'),1,(index+1).ToString("x64"),1,"ticket-package-"+(index+1).ToString("x32")+".tar",0,0,0,Zero);
            records.Add(Sign(identity,sign,records,JournalKind.ImportPrepared,value.Encode()).Bytes);
            DeploymentEvent cancelled=new DeploymentEvent(value.Purpose,value.ReleaseSha256,value.ReleaseSequence,value.Generation,value.HostBootCreation,value.PackageLeaf,0,0,2,H('6'));
            records.Add(Sign(identity,sign,records,JournalKind.Cancelled,cancelled.Encode()).Bytes);
        }
        JournalHistory near=History(identity,records);
        Require(near.Sequence==(ulong)limit && near.FileEnrollments.ActiveCount==count && near.FileEnrollments.AbortReserveCredits==count);assertions++;
        Require(DeploymentHistory.Replay(near).Pending==null);HostedTrustState trust=HostedTrustState.Replay(identity,commission,near,delegate {});
        Require(HostedRuntimeState.Replay(identity,commission.Baseline,trust,near,delegate {}).Pending==null);assertions++;
        DeploymentEvent unrelated=new DeploymentEvent(1,H('7'),1,H('8'),1,"ticket-package-"+new string('9',32)+".tar",0,0,0,Zero);
        JournalEntry stolen=Sign(identity,sign,records,JournalKind.ImportPrepared,unrelated.Encode());int staged=0,nv=0;
        Refuse(delegate {HostedJournalCapacity.BeforeStage(identity,near,stolen,delegate {staged++;nv++;return 1;});});
        Require(staged==0 && nv==0 && near.FileEnrollments.ActiveCount==count);assertions++;
        string first=1.ToString("x64");FileEnrollmentIntent revoke=Proposal(read,FileEnrollmentAction.Revoke,first,generations[first]+1,controls[first].RecordSha256,registry,near.Head,0,0);
        JournalEntry attempted=Event(identity,sign,time,records,revoke,new byte[0]);HostedJournalCapacity.Require(identity,near,attempted);
        Require(near.FileEnrollments.ActiveCount==count && near.FileEnrollments.AbortReserveCredits==count);assertions++;
        JournalEntry aborted=AbortReplacement(identity,sign,records,attempted);HostedJournalCapacity.Require(identity,near,aborted);records.Add(aborted.Bytes);
        JournalHistory after=History(identity,records);Require(after.FileEnrollments.ActiveCount==count && after.FileEnrollments.AbortReserveCredits==count-1);assertions++;
        Require(near.Reconcile(identity,aborted.Bytes,near.Head)==RecoveryPhase.PreparedNotExtended && near.Reconcile(identity,aborted.Bytes,aborted.NextHead)==RecoveryPhase.ExtendedNotPublished && after.Reconcile(identity,aborted.Bytes,after.Head)==RecoveryPhase.AlreadyPublished);assertions++;
        for(int index=1;index<=count;index++) {
            string id=index.ToString("x64");EnrolledFileEntry prior=after.FileEnrollments.Find(id);
            revoke=Proposal(read,FileEnrollmentAction.Revoke,id,prior.Policy.Generation+1,prior.RecordSha256,after.FileEnrollments.SourceSha256,after.Head,0,0);
            JournalEntry terminal=Event(identity,sign,time,records,revoke,new byte[0]);HostedJournalCapacity.Require(identity,after,terminal);
            if(count==1) {
                Require(after.Sequence==1023 && after.FileEnrollments.AbortReserveCredits==0 && terminal.Sequence==1024);assertions++;
                JournalEntry secondAbort=AbortReplacement(identity,sign,records,terminal);
                byte[] pending=terminal.Bytes;int effects=0;
                Refuse(delegate {HostedJournalCapacity.BeforeStage(identity,after,secondAbort,delegate {effects++;pending=new byte[0];return 1;});});
                Require(effects==0 && Wire.Equal(pending,terminal.Bytes) && after.Reconcile(identity,pending,after.Head)==RecoveryPhase.PreparedNotExtended);assertions++;
                Refuse(delegate {HostedJournalCapacity.Require(identity,after,Sign(identity,sign,records,JournalKind.ImportPrepared,unrelated.Encode()));});assertions++;
            }
            records.Add(terminal.Bytes);after=History(identity,records);
        }
        Require(after.FileEnrollments.ActiveCount==0 && after.FileEnrollments.AbortReserveCredits==0);assertions++;
        Require(count!=1 || after.Sequence==1024);assertions++;
        Refuse(delegate {JournalEntry.Prepare(identity,1025,JournalKind.Cancelled,after.Head,after.Record,identity.FirstAdminSid,unrelated.Encode());});assertions++;
        return assertions;
    }
    public static int Run(string workspace,AuthorityIdentity identity,Func<byte[],byte[]> authority,Func<byte[],byte[]> publisher,Func<byte[],byte[]> time,EnrolledReadIntent read,byte[] snapshot,byte[] content)
    {
        int assertions=0;RuntimeBundle baseline=new RuntimeBundle(new RuntimeComponent[]{new RuntimeComponent("Luma.HostedAuthority.exe",64,identity.ServiceSha256),new RuntimeComponent("Luma.PackageInspector.dll",64,H('1')),new RuntimeComponent("Luma.PlatformCustody.dll",64,H('2')),new RuntimeComponent("Luma.PlatformSignature.dll",64,H('3'))});
        CommissionIntent commission=new CommissionIntent(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,identity.ReleaseKey,identity.TimeKey,identity.ServiceSha256,identity.WslSha256,"https://time.example.invalid/luma/challenge",baseline);
        List<byte[]> initial=new List<byte[]>();initial.Add(Sign(identity,authority,initial,JournalKind.Commission,commission.GenesisPayload(identity)).Bytes);JournalHistory first=History(identity,initial);EnrolledFileRegistry empty=first.FileEnrollments;
        Require(empty.IdentityCount==0 && empty.ActiveCount==0 && empty.ControlCount==0 && empty.SourceSha256!=Zero);assertions++;
        FileEnrollmentIntent create=Proposal(read,FileEnrollmentAction.Create,H('1'),1,Zero,empty.SourceSha256,first.Head,1000,1000000);
        Require(Wire.Equal(create.Encode(),FileEnrollmentIntent.Decode(create.Encode()).Encode()));assertions++;
        JournalEntry enrolled=Event(identity,authority,time,initial,create,snapshot);List<byte[]> one=With(initial,enrolled);JournalHistory active=History(identity,one);EnrolledFileEntry entry=active.FileEnrollments.Find(create.Enrollment);
        Require(entry!=null && !entry.Revoked && entry.RecordSha256==enrolled.RecordSha256 && active.FileEnrollments.SourceSha256==enrolled.RecordSha256 && active.FileEnrollments.ActiveCount==1);entry.RequireSnapshot(snapshot);assertions++;
        Require(first.Reconcile(identity,enrolled.Bytes,first.Head)==RecoveryPhase.PreparedNotExtended && first.FileEnrollments.Find(create.Enrollment)==null);assertions++;
        Require(first.Reconcile(identity,enrolled.Bytes,enrolled.NextHead)==RecoveryPhase.ExtendedNotPublished);assertions++;
        Require(active.Reconcile(identity,enrolled.Bytes,active.Head)==RecoveryPhase.AlreadyPublished);assertions++;
        Refuse(delegate {first.Reconcile(identity,enrolled.Bytes,H('9'));});assertions++;
        Require(DeploymentHistory.Replay(active).Pending==null);HostedTrustState trust=HostedTrustState.Replay(identity,commission,active,delegate {});Require(HostedRuntimeState.Replay(identity,baseline,trust,active,delegate {}).Pending==null);assertions++;
        PersistentReadSelection selection=new PersistentReadSelection(create.Enrollment,1,entry.RecordSha256,active.FileEnrollments.SourceSha256,active.Head);Require(selection.Match(active.FileEnrollments,active.Head,read)==entry);assertions++;
        Require(Wire.Equal(selection.Encode(),PersistentReadSelection.Decode(selection.Encode()).Encode()));assertions++;
        Refuse(delegate {PersistentReadSelection.Decode(Wire.Join(selection.Encode(),new byte[]{0}));});assertions++;
        string[] selectedArgs={"read-persistent-file",selection.Enrollment,"1",selection.EntrySha256,selection.RegistrySha256,selection.JournalHead,read.Installation,read.Root,read.RelativePath,read.Bytes.ToString(CultureInfo.InvariantCulture),read.Sha256};
        using(IDisposable client=(IDisposable)New("HostedPersistentReadInputs",(object)selectedArgs)) {
            Refuse(delegate {Call(client,"Complete",new byte[]{1});});assertions++;
            byte[] oldReview;using(Wire.Writer priorReview=new Wire.Writer("luma-windows-hosted-read-review-v1")) {priorReview.Blob(read.Encode(),2048);priorReview.Blob(snapshot,4096);oldReview=priorReview.Bytes();}
            Refuse(delegate {Call(client,"Reviewed",oldReview,H('c'));});assertions++;
            using(Wire.Writer mismatched=new Wire.Writer("luma-windows-hosted-persistent-read-review-v1")) {mismatched.Blob(new PersistentReadSelection(selection.Enrollment,2,selection.EntrySha256,selection.RegistrySha256,selection.JournalHead).Encode(),512);mismatched.Blob(oldReview,8192);Refuse(delegate {Call(client,"Reviewed",mismatched.Bytes(),H('c'));});assertions++;}
            using(Wire.Writer reviewed=new Wire.Writer("luma-windows-hosted-persistent-read-review-v1")) {reviewed.Blob(selection.Encode(),512);reviewed.Blob(oldReview,8192);Call(client,"Reviewed",reviewed.Bytes(),H('c'));}
            object receive=client.GetType().GetField("Read",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(client);object delivery=New("EnrolledReadDelivery",read,H('c'),Wire.Hash(snapshot));Call(delivery,"Begin",Wire.Hash(read.Encode()),Wire.Hash(snapshot));
            for(int offset=0;offset<content.Length;offset+=32768) {byte[] chunk=(byte[])Call(delivery,"Chunk",content,offset);byte[] ack=(byte[])Call(receive,"Part",chunk);Call(delivery,"Acknowledge",ack,content);Array.Clear(chunk,0,chunk.Length);Array.Clear(ack,0,ack.Length);}
            byte[] receipt=(byte[])Call(delivery,"Complete");Refuse(delegate {Call(client,"Complete",receipt);});assertions++;
            using(Wire.Writer changed=new Wire.Writer("luma-windows-hosted-persistent-read-completed-v1")) {changed.Blob(new PersistentReadSelection(selection.Enrollment,1,H('9'),selection.RegistrySha256,selection.JournalHead).Encode(),512);changed.Blob(receipt,2048);Refuse(delegate {Call(client,"Complete",changed.Bytes());});assertions++;}
            using(Wire.Writer completed=new Wire.Writer("luma-windows-hosted-persistent-read-completed-v1")) {completed.Blob(selection.Encode(),512);completed.Blob(receipt,2048);Call(client,"Complete",completed.Bytes());Require(((string)Call(client,"Summary")).Contains("existing persistent enrollment was selected"));assertions++;Refuse(delegate {Call(client,"Complete",completed.Bytes());});assertions++;}
        }
        object controlClient=New("HostedEnrollmentInputs",Wire.Hex(create.Encode()));using(Wire.Writer exactControl=new Wire.Writer("luma-windows-hosted-file-enrollment-review-v1")) {exactControl.Blob(create.Encode(),2048);exactControl.Blob(snapshot,4096);Call(controlClient,"Reviewed",exactControl.Bytes());assertions++;}
        Refuse(delegate {new PersistentReadSelection(create.Enrollment,2,entry.RecordSha256,active.FileEnrollments.SourceSha256,active.Head).Match(active.FileEnrollments,active.Head,read);});assertions++;
        Refuse(delegate {new PersistentReadSelection(create.Enrollment,1,H('9'),active.FileEnrollments.SourceSha256,active.Head).Match(active.FileEnrollments,active.Head,read);});assertions++;
        Refuse(delegate {new PersistentReadSelection(create.Enrollment,1,entry.RecordSha256,H('9'),active.Head).Match(active.FileEnrollments,active.Head,read);});assertions++;
        Refuse(delegate {selection.Match(active.FileEnrollments,H('9'),read);});assertions++;
        Refuse(delegate {selection.Match(active.FileEnrollments,active.Head,new EnrolledReadIntent(read.Installation,read.Owner,read.Root,read.RelativePath,read.Bytes-1,read.Sha256));});assertions++;
        Refuse(delegate {FileEnrollmentIntent.Decode(Wire.Join(create.Encode(),new byte[]{0}));});assertions++;
        Refuse(delegate {new FileEnrollmentIntent((FileEnrollmentAction)4,H('2'),1,Zero,empty.SourceSha256,first.Head,1000,1000000,read);});assertions++;
        Refuse(delegate {Proposal(read,FileEnrollmentAction.Create,H('2'),1,Zero,empty.SourceSha256,first.Head,1000,1000+FileEnrollmentIntent.MaximumLifetimeMilliseconds+1);});assertions++;
        Refuse(delegate {Proposal(read,FileEnrollmentAction.Supersede,H('1'),64,enrolled.RecordSha256,active.FileEnrollments.SourceSha256,active.Head,1000,1000000);});assertions++;
        Refuse(delegate {Proposal(read,FileEnrollmentAction.Revoke,H('1'),2,enrolled.RecordSha256,active.FileEnrollments.SourceSha256,active.Head,1000,1000000);});assertions++;
        FileEnrollmentIntent stale=Proposal(read,FileEnrollmentAction.Supersede,H('1'),2,entry.RecordSha256,active.FileEnrollments.SourceSha256,H('9'),1000,1000001);Refuse(delegate {Event(identity,authority,time,one,stale,snapshot);});assertions++;
        FileEnrollmentIntent wrongRegistry=Proposal(read,FileEnrollmentAction.Supersede,H('1'),2,entry.RecordSha256,H('9'),active.Head,1000,1000001);Refuse(delegate {History(identity,With(one,Event(identity,authority,time,one,wrongRegistry,snapshot)));});assertions++;
        FileEnrollmentIntent wrongPrior=Proposal(read,FileEnrollmentAction.Supersede,H('1'),2,H('9'),active.FileEnrollments.SourceSha256,active.Head,1000,1000001);Refuse(delegate {History(identity,With(one,Event(identity,authority,time,one,wrongPrior,snapshot)));});assertions++;
        FileEnrollmentIntent noop=Proposal(read,FileEnrollmentAction.Supersede,H('1'),2,entry.RecordSha256,active.FileEnrollments.SourceSha256,active.Head,1000,1000000);Refuse(delegate {History(identity,With(one,Event(identity,authority,time,one,noop,snapshot)));});assertions++;
        FileEnrollmentIntent replace=Proposal(read,FileEnrollmentAction.Supersede,H('1'),2,entry.RecordSha256,active.FileEnrollments.SourceSha256,active.Head,1000,1000001);JournalEntry replaced=Event(identity,authority,time,one,replace,snapshot);List<byte[]> two=With(one,replaced);JournalHistory current=History(identity,two);Require(current.FileEnrollments.Find(H('1')).Policy.Generation==2);assertions++;
        Refuse(delegate {selection.Match(current.FileEnrollments,current.Head,read);});assertions++;
        Refuse(delegate {History(identity,With(two,replaced));});assertions++;
        FileEnrollmentIntent revoke=Proposal(read,FileEnrollmentAction.Revoke,H('1'),3,replaced.RecordSha256,current.FileEnrollments.SourceSha256,current.Head,0,0);FileEnrollmentRecord revokedRecord=Record(identity,revoke,new byte[0],time);
        Refuse(delegate {Sign(identity,authority,two,JournalKind.FileEnrolled,revokedRecord.Encode());});assertions++;
        Refuse(delegate {Record(identity,revoke,snapshot,time);});assertions++;
        FileEnrollmentRecord wrongProof=new FileEnrollmentRecord(replace,H('b'),snapshot,new TimeAttestation(identity.Installation,H('7'),H('8'),2000,2010).Encode(),time(new TimeAttestation(identity.Installation,H('7'),H('8'),2000,2010).Encode()));Refuse(delegate {History(identity,With(one,Sign(identity,authority,one,JournalKind.FileEnrolled,wrongProof.Encode())));});assertions++;
        LiveUtcWindow expired=new LiveUtcWindow(identity,Wire.Hash(read.Encode()),entry.NotBefore,entry.Expires);TimeAttestation expiry=new TimeAttestation(identity.Installation,expired.Nonce,Wire.Hash(read.Encode()),entry.Expires-10,entry.Expires);Refuse(delegate {expired.Accept(expiry.Encode(),time(expiry.Encode()));});assertions++;
        // A valid independently reviewed UTC revocation fences later controls.
        HostedTrustState initialTrust=HostedTrustState.Replay(identity,commission,first,delegate {});TrustChange stopTime=new TrustChange(4,identity.Installation,1,initialTrust.SourceSha256,1000,1000000,identity.ReleaseKey,identity.TimeKey,commission.TimeEndpoint);TimeAttestation stopProof=new TimeAttestation(identity.Installation,Wire.Hex(Wire.Random(32)),Wire.Hash(stopTime.Encode()),2000,2010);
        TrustRecord stopRecord=new TrustRecord(stopTime,new byte[64],new byte[64],stopProof.Encode(),time(stopProof.Encode()),new byte[0],new byte[0]);List<byte[]> stopped=With(initial,Sign(identity,authority,initial,JournalKind.TrustChanged,stopRecord.Encode()));JournalHistory stoppedHistory=History(identity,stopped);Require(HostedTrustState.Replay(identity,commission,stoppedHistory,delegate {}).TimeRevoked);assertions++;
        FileEnrollmentIntent afterStop=Proposal(read,FileEnrollmentAction.Create,H('1'),1,Zero,empty.SourceSha256,stoppedHistory.Head,1000,1000000);Refuse(delegate {History(identity,With(stopped,Event(identity,authority,time,stopped,afterStop,snapshot)));});assertions++;
        HostedRuntimeState initialRuntime=HostedRuntimeState.Replay(identity,baseline,initialTrust,first,delegate {});RuntimeComponent[] next=baseline.Components;next[0]=new RuntimeComponent(next[0].Name,64,H('8'));RuntimeUpdate update=new RuntimeUpdate(identity.Installation,1,initialRuntime.SourceSha256,1000,1000000,new RuntimeBundle(next),identity.WslSha256);TimeAttestation updateProof=new TimeAttestation(identity.Installation,Wire.Hex(Wire.Random(32)),Wire.Hash(update.Encode()),2000,2010);
        RuntimePreparation preparation=new RuntimePreparation(update,H('9'),publisher(update.SigningInput()),updateProof.Encode(),time(updateProof.Encode()));List<byte[]> pendingRuntime=With(initial,Sign(identity,authority,initial,JournalKind.RuntimePrepared,preparation.Encode()));JournalHistory pendingHistory=History(identity,pendingRuntime);Require(HostedRuntimeState.Replay(identity,baseline,HostedTrustState.Replay(identity,commission,pendingHistory,delegate {}),pendingHistory,delegate {}).Pending!=null);assertions++;
        FileEnrollmentIntent afterRuntime=Proposal(read,FileEnrollmentAction.Create,H('1'),1,Zero,empty.SourceSha256,pendingHistory.Head,1000,1000000);Refuse(delegate {History(identity,With(pendingRuntime,Event(identity,authority,time,pendingRuntime,afterRuntime,snapshot)));});assertions++;
        // Actual finite signed histories reach both limits without consuming the
        // last generation/control slots needed for every remaining revocation.
        List<byte[]> bounded=new List<byte[]>(initial);Dictionary<string,JournalEntry> last=new Dictionary<string,JournalEntry>();Dictionary<string,ulong> generation=new Dictionary<string,ulong>();string registry=empty.SourceSha256,head=first.Head;
        for(int index=1;index<=64;index++) {string id=index.ToString("x64");FileEnrollmentIntent grant=Proposal(read,FileEnrollmentAction.Create,id,1,Zero,registry,head,1000,1000000);JournalEntry item=Event(identity,authority,time,bounded,grant,snapshot);bounded.Add(item.Bytes);last[id]=item;generation[id]=1;registry=item.RecordSha256;head=item.NextHead;}
        JournalHistory fullIds=History(identity,bounded);Require(fullIds.FileEnrollments.IdentityCount==64 && fullIds.FileEnrollments.ActiveCount==64);assertions++;
        FileEnrollmentIntent id65=Proposal(read,FileEnrollmentAction.Create,65.ToString("x64"),1,Zero,registry,head,1000,1000000);Refuse(delegate {History(identity,With(bounded,Event(identity,authority,time,bounded,id65,snapshot)));});assertions++;
        for(int index=0;index<128;index++) {string id=(index%64+1).ToString("x64");ulong gen=++generation[id];FileEnrollmentIntent extend=Proposal(read,FileEnrollmentAction.Supersede,id,gen,last[id].RecordSha256,registry,head,1000,1000000+gen);JournalEntry item=Event(identity,authority,time,bounded,extend,snapshot);bounded.Add(item.Bytes);last[id]=item;registry=item.RecordSha256;head=item.NextHead;}
        JournalHistory reserved=History(identity,bounded);Require(reserved.FileEnrollments.ControlCount==192 && reserved.FileEnrollments.ActiveCount==64);assertions++;
        string firstId=1.ToString("x64");FileEnrollmentIntent exhausted=Proposal(read,FileEnrollmentAction.Supersede,firstId,generation[firstId]+1,last[firstId].RecordSha256,registry,head,1000,1000010);Refuse(delegate {History(identity,With(bounded,Event(identity,authority,time,bounded,exhausted,snapshot)));});assertions++;
        for(int index=1;index<=64;index++) {string id=index.ToString("x64");FileEnrollmentIntent removal=Proposal(read,FileEnrollmentAction.Revoke,id,++generation[id],last[id].RecordSha256,registry,head,0,0);JournalEntry item=Event(identity,authority,time,bounded,removal,new byte[0]);bounded.Add(item.Bytes);last[id]=item;registry=item.RecordSha256;head=item.NextHead;}
        JournalHistory allRevoked=History(identity,bounded);Require(allRevoked.FileEnrollments.ControlCount==256 && allRevoked.FileEnrollments.ActiveCount==0 && allRevoked.FileEnrollments.IdentityCount==64);assertions++;
        Refuse(delegate {new PersistentReadSelection(firstId,generation[firstId],last[firstId].RecordSha256,registry,head).Match(allRevoked.FileEnrollments,head,read);});assertions++;
        FileEnrollmentIntent resurrect=Proposal(read,FileEnrollmentAction.Create,firstId,1,Zero,registry,head,1000,1000000);Refuse(delegate {History(identity,With(bounded,Event(identity,authority,time,bounded,resurrect,snapshot)));});assertions++;
        List<byte[]> versions=new List<byte[]>(initial);registry=empty.SourceSha256;head=first.Head;JournalEntry prior=null;
        for(ulong gen=1;gen<=63;gen++) {FileEnrollmentIntent nextVersion=Proposal(read,gen==1?FileEnrollmentAction.Create:FileEnrollmentAction.Supersede,H('4'),gen,prior==null?Zero:prior.RecordSha256,registry,head,1000,1000000+gen);prior=Event(identity,authority,time,versions,nextVersion,snapshot);versions.Add(prior.Bytes);registry=prior.RecordSha256;head=prior.NextHead;}
        Require(History(identity,versions).FileEnrollments.Find(H('4')).Policy.Generation==63);assertions++;
        FileEnrollmentIntent finalRevoke=Proposal(read,FileEnrollmentAction.Revoke,H('4'),64,prior.RecordSha256,registry,head,0,0);versions.Add(Event(identity,authority,time,versions,finalRevoke,new byte[0]).Bytes);Require(History(identity,versions).FileEnrollments.Find(H('4')).Revoked);assertions++;
        // Destructive operations below resolve only this test's newly created
        // one-file fixture, never a caller-selected or installed source.
        string fixtureParent=Path.Combine(Path.GetFullPath(workspace),".luma");Require(Path.GetDirectoryName(read.Root)==fixtureParent && System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(read.Root),"\\Awindows-read-fixtures-[0-9a-f]{32}\\z") && read.RelativePath=="source.bin" && (File.GetAttributes(read.Root)&FileAttributes.ReparsePoint)==0);
        File.Delete(read.Path);Require(!File.Exists(read.Path));JournalEntry removed=Event(identity,authority,time,two,revoke,new byte[0]);JournalHistory missing=History(identity,With(two,removed));Require(missing.FileEnrollments.Find(H('1')).Revoked);assertions++;
        Refuse(delegate {selection.Match(missing.FileEnrollments,missing.Head,read);});assertions++;
        File.WriteAllBytes(read.Path,content);using(WindowsIdentity currentOwner=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate|TokenAccessLevels.Impersonate)) {
            Type type=typeof(EnrolledReadIntent).Assembly.GetType("Luma.Windows.Hosted.EnrolledReadSource",true);using(IDisposable source=(IDisposable)Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{read,currentOwner.AccessToken,new Action(delegate {})},null)) {byte[] changed=(byte[])Call(source,"Snapshot");Refuse(delegate {entry.RequireSnapshot(changed);});assertions++;}
        }
        assertions+=Capacity(identity,authority,time,commission,read,snapshot,1);
        assertions+=Capacity(identity,authority,time,commission,read,snapshot,64);
        return assertions;
    }
}
