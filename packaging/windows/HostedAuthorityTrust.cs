using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security;

namespace Luma.Windows.Hosted
{
    public sealed class TrustChange
    {
        public byte Action {get;private set;}public ulong Generation {get;private set;}
        public string Installation {get;private set;}public string Previous {get;private set;}public string Endpoint {get;private set;}
        public ulong NotBefore {get;private set;}public ulong Expires {get;private set;}
        private readonly byte[] publisher,time;
        public byte[] Publisher {get{return (byte[])publisher.Clone();}}public byte[] Time {get{return (byte[])time.Clone();}}
        public TrustChange(byte action,string installation,ulong generation,string previous,ulong notBefore,ulong expires,byte[] publisher,byte[] time,string endpoint) {
            if(action<1 || action>7 || generation<1 || generation>1024 || notBefore==0 || expires<=notBefore || expires>4102444800000UL || expires-notBefore>604800000UL) throw new InvalidDataException("Closed trust action, generation or validity window differs.");
            Wire.Bytes(installation,32,true);Wire.Bytes(previous,32,true);this.publisher=AuthorityIdentity.Public(publisher);this.time=AuthorityIdentity.Public(time);
            if(Wire.Equal(this.publisher,this.time)) throw new SecurityException("Publisher and UTC keys are independent.");
            Action=action;Installation=installation;Generation=generation;Previous=previous;NotBefore=notBefore;Expires=expires;Endpoint=HostedTimeEndpoint.Validate(endpoint);
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-change-v1")) {
            writer.U8(Action);writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.U64(Generation);writer.Fixed(Wire.Bytes(Previous,32,true),32);writer.U64(NotBefore);writer.U64(Expires);
            writer.Fixed(publisher,72);writer.Fixed(time,72);writer.Text(Endpoint,2048);return writer.Bytes();
        }}
        public static TrustChange Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-trust-change-v1")) {
            TrustChange result=new TrustChange(reader.U8(),Wire.Hex(reader.Fixed(32)),reader.U64(),Wire.Hex(reader.Fixed(32)),reader.U64(),reader.U64(),reader.Fixed(72),reader.Fixed(72),reader.Text(2048));reader.End();return result;
        }}
        public byte[] SigningInput() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-publisher-v1")) {writer.Fixed(Wire.HashBytes(Encode()),32);return writer.Bytes();}}
        public byte[] AcceptanceInput() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-acceptance-v1")) {writer.Fixed(Wire.HashBytes(Encode()),32);return writer.Bytes();}}
        public bool ChangesTime {get{return Action==2 || Action==6 || Action==7;}}
        public bool ChangesPublisher {get{return Action==1 || Action==5 || Action==7;}}
        public bool NeedsOldTime {get{return Action!=6 && Action!=7;}}
    }

    public sealed class LiveUtcWindow
    {
        public string Nonce {get;private set;}private readonly AuthorityIdentity identity;private readonly string source;
        private readonly ulong start,end;private readonly Stopwatch age=Stopwatch.StartNew();private TimeAttestation observed;
        private byte[] signature;
        public LiveUtcWindow(AuthorityIdentity identity,string source,ulong start,ulong end) {
            if(identity==null || start==0 || end<=start || end>4102444800000UL) throw new InvalidDataException("Exact independently signed UTC context required.");Wire.Bytes(source,32,true);
            this.identity=identity;this.source=source;this.start=start;this.end=end;Nonce=Wire.Hex(Wire.Random(32));
        }
        public void Accept(byte[] proof,byte[] actualSignature) {
            if(observed!=null || age.Elapsed.TotalSeconds>=30) throw new SecurityException("UTC challenge was reused or expired.");TimeAttestation value=TimeAttestation.Decode(proof);
            Validate(identity,source,start,end,value,actualSignature);if(value.Nonce!=Nonce) throw new SecurityException("Fresh UTC nonce differs.");observed=value;signature=Wire.Copy(actualSignature,64,64);Check();
        }
        public void Check() {
            if(observed==null || age.Elapsed.TotalSeconds>=30) throw new SecurityException("Fresh independent UTC is unavailable; no wall clock fallback.");
            ulong elapsed=checked((ulong)Math.Ceiling(age.Elapsed.TotalMilliseconds*1.001)+1);
            if(observed.LowerMilliseconds<start || checked(observed.UpperMilliseconds+elapsed)>=end) throw new SecurityException("Complete conservative UTC interval is outside its half-open lifetime.");
        }
        public byte[] Proof {get{Check();return observed.Encode();}}public byte[] Signature {get{Check();return (byte[])signature.Clone();}}
        internal static void Validate(AuthorityIdentity identity,string source,ulong start,ulong end,TimeAttestation value,byte[] signature) {
            if(value.Installation!=identity.Installation || value.ReleaseSha256!=source || value.LowerMilliseconds<start || value.UpperMilliseconds>=end ||
                !Luma.Windows.PlatformSignature.Verify(identity.TimeKey,value.Encode(),Wire.Copy(signature,64,64))) throw new SecurityException("Exact independent UTC source, interval, installation or signature differs.");
        }
    }

    public sealed class TrustRecord
    {
        public TrustChange Change {get;private set;}private readonly byte[] publisher,acceptance,oldTime,oldSignature,newTime,newSignature;
        public TrustRecord(TrustChange change,byte[] publisher,byte[] acceptance,byte[] oldTime,byte[] oldSignature,byte[] newTime,byte[] newSignature) {
            if(change==null) throw new ArgumentNullException("change");Change=change;this.publisher=Wire.Copy(publisher,64,64);this.acceptance=Wire.Copy(acceptance,64,64);
            this.oldTime=Wire.Copy(oldTime,0,512);this.oldSignature=Wire.Copy(oldSignature,0,64);this.newTime=Wire.Copy(newTime,0,512);this.newSignature=Wire.Copy(newSignature,0,64);
            if((change.NeedsOldTime && (this.oldTime.Length==0 || this.oldSignature.Length!=64)) || (!change.NeedsOldTime && (this.oldTime.Length!=0 || this.oldSignature.Length!=0)) ||
                (change.ChangesTime && (this.newTime.Length==0 || this.newSignature.Length!=64)) || (!change.ChangesTime && (this.newTime.Length!=0 || this.newSignature.Length!=0))) throw new SecurityException("Trust action requires its exact old/new UTC proof modes.");
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-record-v1")) {
            writer.Blob(Change.Encode(),3072);writer.Fixed(publisher,64);writer.Fixed(acceptance,64);writer.Blob(oldTime,512);writer.Blob(oldSignature,64);writer.Blob(newTime,512);writer.Blob(newSignature,64);return writer.Bytes();
        }}
        public static TrustRecord Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-trust-record-v1")) {
            TrustRecord result=new TrustRecord(TrustChange.Decode(reader.Blob(3072)),reader.Fixed(64),reader.Fixed(64),reader.Blob(512),reader.Blob(64),reader.Blob(512),reader.Blob(64));reader.End();return result;
        }}
        internal void Validate(HostedTrustState state) {
            state.Validate(Change,publisher,acceptance);string source=Wire.Hash(Change.Encode());
            if(Change.Action==2 && (state.Pending==null || !state.Pending.Matches(Change,publisher,acceptance,oldTime,oldSignature))) throw new SecurityException("Normal UTC handoff requires its exact independently committed old-key preparation.");
            if(Change.Action!=2 && state.Pending!=null) throw new SecurityException("A different trust action cannot bypass an outstanding prepared handoff.");
            if(Change.NeedsOldTime) LiveUtcWindow.Validate(state.CurrentIdentity,source,Change.NotBefore,Change.Expires,TimeAttestation.Decode(oldTime),oldSignature);
            if(Change.ChangesTime) LiveUtcWindow.Validate(state.ProposedIdentity(Change),source,Change.NotBefore,Change.Expires,TimeAttestation.Decode(newTime),newSignature);
        }
    }

    public sealed class TrustPreparation
    {
        public TrustChange Change {get;private set;}private readonly byte[] publisher,acceptance,proof,signature;
        public byte[] PublisherSignature {get{return (byte[])publisher.Clone();}}public byte[] AcceptanceSignature {get{return (byte[])acceptance.Clone();}}
        public byte[] OldProof {get{return (byte[])proof.Clone();}}public byte[] OldSignature {get{return (byte[])signature.Clone();}}
        public TrustPreparation(TrustChange change,byte[] publisher,byte[] acceptance,byte[] proof,byte[] signature) {
            if(change==null || change.Action!=2) throw new SecurityException("Only a normal old-to-new UTC handoff has a preparation phase.");Change=change;
            this.publisher=Wire.Copy(publisher,64,64);this.acceptance=Wire.Copy(acceptance,64,64);this.proof=Wire.Copy(proof,1,512);this.signature=Wire.Copy(signature,64,64);
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-prepared-v1")) {writer.Blob(Change.Encode(),3072);writer.Fixed(publisher,64);writer.Fixed(acceptance,64);writer.Blob(proof,512);writer.Fixed(signature,64);return writer.Bytes();}}
        public static TrustPreparation Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-trust-prepared-v1")) {TrustPreparation result=new TrustPreparation(TrustChange.Decode(reader.Blob(3072)),reader.Fixed(64),reader.Fixed(64),reader.Blob(512),reader.Fixed(64));reader.End();return result;}}
        internal void Validate(HostedTrustState state) {
            if(state.Pending!=null) throw new SecurityException("A prepared UTC handoff already exists.");state.Validate(Change,publisher,acceptance);
            LiveUtcWindow.Validate(state.CurrentIdentity,Wire.Hash(Change.Encode()),Change.NotBefore,Change.Expires,TimeAttestation.Decode(proof),signature);
        }
        internal bool Matches(TrustChange change,byte[] publisher,byte[] acceptance,byte[] proof,byte[] signature) {
            return Wire.Equal(Change.Encode(),change.Encode()) && Wire.Equal(this.publisher,publisher) && Wire.Equal(this.acceptance,acceptance) && Wire.Equal(this.proof,proof) && Wire.Equal(this.signature,signature);
        }
    }

    public sealed class TrustCancellation
    {
        public string PreparedSha256 {get;private set;}public bool ProposedTime {get;private set;}private readonly byte[] proof,signature;
        public TrustCancellation(string prepared,bool proposed,byte[] proof,byte[] signature) {Wire.Bytes(prepared,32,true);PreparedSha256=prepared;ProposedTime=proposed;this.proof=Wire.Copy(proof,1,512);this.signature=Wire.Copy(signature,64,64);}
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-cancelled-v1")) {writer.Fixed(Wire.Bytes(PreparedSha256,32,true),32);writer.U8(ProposedTime?(byte)1:(byte)0);writer.Blob(proof,512);writer.Fixed(signature,64);return writer.Bytes();}}
        public static TrustCancellation Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-trust-cancelled-v1")) {string prepared=Wire.Hex(reader.Fixed(32));byte mode=reader.U8();if(mode>1) throw new SecurityException("Unknown trust cancellation UTC mode.");TrustCancellation result=new TrustCancellation(prepared,mode==1,reader.Blob(512),reader.Fixed(64));reader.End();return result;}}
        internal void Validate(HostedTrustState state) {
            if(state.Pending==null || PreparedSha256!=Wire.Hash(state.Pending.Encode())) throw new SecurityException("Cancellation has no exact outstanding handoff.");
            TrustChange change=state.Pending.Change;LiveUtcWindow.Validate(ProposedTime?state.ProposedIdentity(change):state.CurrentIdentity,Wire.Hash(change.Encode()),1,4102444800000UL,TimeAttestation.Decode(proof),signature);
        }
    }

    public sealed class HostedTrustState
    {
        private readonly AuthorityIdentity original;private readonly HashSet<string> retired=new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string,AuthorityIdentity> admissions=new Dictionary<string,AuthorityIdentity>(StringComparer.Ordinal);
        private readonly Dictionary<ulong,RecordedTrust> recorded=new Dictionary<ulong,RecordedTrust>();
        public AuthorityIdentity CurrentIdentity {get;private set;}public string Endpoint {get;private set;}public string SourceSha256 {get;private set;}
        public ulong Generation {get;private set;}public bool PublisherRevoked {get;private set;}public bool TimeRevoked {get;private set;}
        public TrustPreparation Pending {get;private set;}
        private HostedTrustState(AuthorityIdentity identity,CommissionIntent intent) {
            original=identity;CurrentIdentity=identity;Endpoint=intent.TimeEndpoint;
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-genesis-v1")) {writer.Fixed(Wire.HashBytes(identity.Encode()),32);writer.Text(Endpoint,2048);SourceSha256=Wire.Hash(writer.Bytes());}
        }
        public static HostedTrustState Replay(AuthorityIdentity identity,CommissionIntent intent,JournalHistory history,Action check) {
            if(identity==null || intent==null || history==null || check==null) throw new ArgumentNullException("identity");intent.Matches(identity);check();HostedTrustState state=new HostedTrustState(identity,intent);
            foreach(JournalEntry entry in history.Entries) {
                state.recorded.Add(entry.Sequence,new RecordedTrust(state.CurrentIdentity,!state.PublisherRevoked && !state.TimeRevoked && state.Pending==null,!state.TimeRevoked));
                check();if(entry.Kind==JournalKind.TrustChanged) {TrustRecord record=TrustRecord.Decode(entry.Payload);record.Validate(state);state.Apply(record);state.Pending=null;}
                else if(entry.Kind==JournalKind.TrustPrepared) {TrustPreparation preparation=TrustPreparation.Decode(entry.Payload);preparation.Validate(state);state.Pending=preparation;}
                else if(entry.Kind==JournalKind.TrustCancelled) {
                    TrustCancellation cancellation=TrustCancellation.Decode(entry.Payload);cancellation.Validate(state);
                    state.Generation=state.Pending.Change.Generation;state.SourceSha256=Wire.Hash(cancellation.Encode());
                    if(cancellation.ProposedTime) {state.retired.Add(Wire.Hash(state.CurrentIdentity.TimeKey));state.TimeRevoked=true;}state.Pending=null;
                }
                else if(entry.Kind==JournalKind.ImportPrepared || entry.Kind==JournalKind.ActivationPrepared || entry.Kind==JournalKind.ComputePrepared) {
                    DeploymentEvent admission=DeploymentEvent.Decode(entry.Payload);if(state.PublisherRevoked || state.TimeRevoked || state.Pending!=null || state.admissions.ContainsKey(admission.Generation)) throw new SecurityException("Deployment admission crossed a revoked/prepared trust generation or duplicate authority.");
                    state.admissions.Add(admission.Generation,state.CurrentIdentity);
                }
            }
            check();return state;
        }
        public RecordedTrust At(ulong sequence) {RecordedTrust value;if(!recorded.TryGetValue(sequence,out value)) throw new SecurityException("No genuine chronological trust observation exists for this journal sequence.");return value;}
        public AuthorityIdentity ForRelease() {if(PublisherRevoked || TimeRevoked || Pending!=null) throw new SecurityException("Release/UTC anchor is revoked or a handoff is pending; new effects refuse until explicit trusted recovery.");return CurrentIdentity;}
        public AuthorityIdentity ForCleanup(string generation) {
            AuthorityIdentity prior;if(TimeRevoked || !admissions.TryGetValue(generation,out prior)) throw new SecurityException("Cleanup requires its genuine original publisher and a currently non-revoked independent UTC anchor.");
            return new AuthorityIdentity(original.Domain,original.Installation,original.FirstAdminSid,original.Environment,prior.ReleaseKey,CurrentIdentity.TimeKey,original.AuthorityKey,original.ServiceSha256,original.WslSha256);
        }
        public AuthorityIdentity ProposedIdentity(TrustChange change) {return new AuthorityIdentity(original.Domain,original.Installation,original.FirstAdminSid,original.Environment,change.Publisher,change.Time,original.AuthorityKey,original.ServiceSha256,original.WslSha256);}
        public void Validate(TrustChange change,byte[] publisherSignature,byte[] acceptanceSignature) {
            if(change==null || change.Installation!=original.Installation || change.Previous!=SourceSha256 || change.Generation!=checked(Generation+1)) throw new SecurityException("Trust transition installation, predecessor or generation differs.");
            bool pubDifferent=!Wire.Equal(change.Publisher,CurrentIdentity.ReleaseKey),timeDifferent=!Wire.Equal(change.Time,CurrentIdentity.TimeKey);
            if(pubDifferent!=change.ChangesPublisher || timeDifferent!=change.ChangesTime || (!change.ChangesTime && change.Endpoint!=Endpoint)) throw new SecurityException("Trust action substituted unchanged keys or endpoint.");
            ProposedIdentity(change);
            if(change.ChangesPublisher && retired.Contains(Wire.Hash(change.Publisher)) || change.ChangesTime && retired.Contains(Wire.Hash(change.Time))) throw new SecurityException("Revoked or retired trust anchors cannot be reused.");
            if((change.Action==1 || change.Action==2) && (PublisherRevoked || TimeRevoked) || change.Action==3 && PublisherRevoked || change.Action==4 && TimeRevoked ||
                change.Action==5 && (!PublisherRevoked || TimeRevoked) || change.Action==6 && (!TimeRevoked || PublisherRevoked) || change.Action==7 && (!TimeRevoked && !PublisherRevoked)) throw new SecurityException("Trust action does not match the actual revocation/recovery state.");
            bool requiresPublisher=change.Action==1 || change.Action==2 || change.Action==6;
            if(requiresPublisher) {if(!Luma.Windows.PlatformSignature.Verify(CurrentIdentity.ReleaseKey,change.SigningInput(),Wire.Copy(publisherSignature,64,64))) throw new SecurityException("Current non-revoked publisher did not sign the exact trust transition.");}
            else if(Wire.Hex(Wire.Copy(publisherSignature,64,64))!=new string('0',128)) throw new SecurityException("Admin-only revocation/recovery does not treat a revoked/arbitrary publisher signature as authority.");
            if(change.ChangesPublisher) {if(!Luma.Windows.PlatformSignature.Verify(change.Publisher,change.AcceptanceInput(),Wire.Copy(acceptanceSignature,64,64))) throw new SecurityException("Exact replacement publisher has no real proof of possession.");}
            else if(Wire.Hex(Wire.Copy(acceptanceSignature,64,64))!=new string('0',128)) throw new SecurityException("No replacement publisher proof is permitted for this action.");
            if(change.NeedsOldTime && TimeRevoked) throw new SecurityException("Revoked UTC cannot be used as current time authority.");
        }
        private void Apply(TrustRecord record) {
            TrustChange change=record.Change;
            if(change.ChangesPublisher || change.Action==3) retired.Add(Wire.Hash(CurrentIdentity.ReleaseKey));
            if(change.ChangesTime || change.Action==4) retired.Add(Wire.Hash(CurrentIdentity.TimeKey));
            if(change.ChangesPublisher) PublisherRevoked=false;if(change.ChangesTime) TimeRevoked=false;
            if(change.Action==3) PublisherRevoked=true;if(change.Action==4) TimeRevoked=true;
            CurrentIdentity=ProposedIdentity(change);Endpoint=change.Endpoint;Generation=change.Generation;SourceSha256=Wire.Hash(record.Encode());
        }
    }

    internal static partial class HostedCoordinator
    {
        private static LiveUtcWindow TrustTime(NamedPipeServerStream pipe,AuthorityIdentity identity,string endpoint,TrustChange change,Action original,bool lifetime) {
            original();LiveUtcWindow live=new LiveUtcWindow(identity,Wire.Hash(change.Encode()),lifetime?change.NotBefore:1,lifetime?change.Expires:4102444800000UL);byte[] challenge;
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-utc-challenge-v1")) {writer.Fixed(Wire.Bytes(identity.Installation,32,true),32);writer.Fixed(Wire.Bytes(live.Nonce,32,true),32);writer.Fixed(Wire.HashBytes(change.Encode()),32);challenge=writer.Bytes();}
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-time-relay-v1")) {writer.Text(endpoint,2048);writer.Blob(challenge,1024);Reply(pipe,"utc-challenge",writer.Bytes(),original);}
            byte[] delivery=HostedPipe.Read(pipe,original,TimeSpan.FromSeconds(20));using(Wire.Reader reader=new Wire.Reader(delivery,"luma-windows-hosted-utc-delivery-v1")) {live.Accept(reader.Blob(8192),reader.Fixed(64));reader.End();}original();return live;
        }
        private static void ChangeTrust(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,string operation) {
            byte[] bytes=request.Blob(3072),publisher=request.Fixed(64),acceptance=request.Fixed(64);request.End();TrustChange change=TrustChange.Decode(bytes);
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,RuntimeAccess.Inspect)) {
                JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedTrustState state=authority.Trust;state.Validate(change,publisher,acceptance);
                bool prepare=operation=="trust-prepare",finalize=operation=="trust-finalize",cancel=operation=="trust-cancel" || operation=="trust-quarantine",quarantine=operation=="trust-quarantine";
                if(prepare && (change.Action!=2 || state.Pending!=null) || finalize && (change.Action!=2 || state.Pending==null) || cancel && state.Pending==null ||
                    operation=="trust" && (change.Action==2 || state.Pending!=null)) throw new SecurityException("Exact trust preparation/finalization/cancellation purpose differs; normal UTC rotation is never a one-shot old/new-key assumption.");
                if(state.Pending!=null && !state.Pending.Matches(change,publisher,acceptance,state.Pending.OldProof,state.Pending.OldSignature)) throw new SecurityException("Trust handoff changed its exact committed prepared descriptor or proofs.");
                using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-trust-review-v1")) {
                    writer.Fixed(Wire.HashBytes(bytes),32);writer.Fixed(publisher,64);writer.Fixed(acceptance,64);writer.Fixed(Wire.Bytes(history.Head,32,true),32);writer.Fixed(Wire.Bytes(state.SourceSha256,32,true),32);
                    Review(pipe,operation,writer.Bytes(),"Exact "+operation+" action "+change.Action+"; generation "+change.Generation+"\nDescriptor SHA256: "+Wire.Hash(bytes)+
                        "\nPublisher key SHA256: "+Wire.Hash(change.Publisher)+"\nUTC key SHA256: "+Wire.Hash(change.Time)+"\nUTC endpoint: "+change.Endpoint+
                        "\nActions: 1 rotate publisher, 2 rotate UTC, 3 revoke publisher, 4 revoke UTC, 5 recover revoked publisher, 6 recover revoked UTC, 7 recover both revoked anchors. The actual original Admin assigns these exact pins; signatures alone never establish custody. Existing TPM authority key/NV is unchanged. No guest effect or production qualification.",original);
                }
                LiveUtcWindow oldTime=(!finalize && change.NeedsOldTime && !quarantine)?TrustTime(pipe,state.CurrentIdentity,state.Endpoint,change,original,!cancel):null;
                LiveUtcWindow newTime=(!prepare && change.ChangesTime && (!cancel || quarantine))?TrustTime(pipe,state.ProposedIdentity(change),change.Endpoint,change,original,!cancel):null;
                Action check=delegate {original();authority.State.Check();if(oldTime!=null) oldTime.Check();if(newTime!=null) newTime.Check();};check();
                if(prepare) {
                    TrustPreparation preparation=new TrustPreparation(change,publisher,acceptance,oldTime.Proof,oldTime.Signature);preparation.Validate(state);
                    authority.Journal.Append(JournalKind.TrustPrepared,actor.Sid,preparation.Encode(),check);
                    JournalHistory prepared=authority.Journal.Read(check);prepared.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedTrustState verified=HostedTrustState.Replay(authority.Identity,authority.Intent,prepared,check);
                    if(verified.Pending==null || !Wire.Equal(verified.Pending.Encode(),preparation.Encode())) throw new SecurityException("Prepared UTC handoff did not reconstruct from actual NV history.");
                    using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-trust-prepared-result-v1")) {result.Fixed(Wire.HashBytes(bytes),32);result.Fixed(Wire.HashBytes(preparation.Encode()),32);result.U8(0);Reply(pipe,"trust-prepared",result.Bytes(),check);}return;
                }
                if(cancel) {
                    LiveUtcWindow observation=quarantine?newTime:oldTime;TrustCancellation cancellation=new TrustCancellation(Wire.Hash(state.Pending.Encode()),quarantine,observation.Proof,observation.Signature);cancellation.Validate(state);
                    authority.Journal.Append(JournalKind.TrustCancelled,actor.Sid,cancellation.Encode(),check);
                    JournalHistory cancelled=authority.Journal.Read(check);cancelled.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedTrustState verified=HostedTrustState.Replay(authority.Identity,authority.Intent,cancelled,check);
                    if(verified.Pending!=null || verified.SourceSha256!=Wire.Hash(cancellation.Encode()) || verified.Generation!=change.Generation) throw new SecurityException("Exact UTC handoff cancellation did not reconstruct.");
                    using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-trust-cancelled-result-v1")) {result.Fixed(Wire.HashBytes(bytes),32);result.U64(verified.Generation);result.Fixed(Wire.Bytes(verified.SourceSha256,32,true),32);result.U8(quarantine?(byte)1:(byte)0);result.U8(0);Reply(pipe,"trust-cancelled",result.Bytes(),check);}return;
                }
                TrustRecord record=new TrustRecord(change,publisher,acceptance,finalize?state.Pending.OldProof:oldTime==null?new byte[0]:oldTime.Proof,finalize?state.Pending.OldSignature:oldTime==null?new byte[0]:oldTime.Signature,newTime==null?new byte[0]:newTime.Proof,newTime==null?new byte[0]:newTime.Signature);
                record.Validate(state);authority.Journal.Append(JournalKind.TrustChanged,actor.Sid,record.Encode(),check);
                JournalHistory completed=authority.Journal.Read(check);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedTrustState rebuilt=HostedTrustState.Replay(authority.Identity,authority.Intent,completed,check);
                if(rebuilt.Generation!=change.Generation || rebuilt.SourceSha256!=Wire.Hash(record.Encode())) throw new SecurityException("Actual trust change did not reconstruct exactly.");
                using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-trust-result-v1")) {result.Fixed(Wire.HashBytes(bytes),32);result.U64(rebuilt.Generation);result.Fixed(Wire.Bytes(rebuilt.SourceSha256,32,true),32);result.U8(0);Reply(pipe,"trust-changed",result.Bytes(),check);}
            }
        }
    }
}
