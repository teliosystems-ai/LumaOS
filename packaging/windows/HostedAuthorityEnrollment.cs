using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace Luma.Windows.Hosted
{
    public enum FileEnrollmentAction : byte { Create=1,Supersede=2,Revoke=3 }

    // Stable proposed policy, not a grant. Only the original reviewed Admin
    // command can commit it to the existing signed, NV-backed hosted journal.
    public sealed class FileEnrollmentIntent
    {
        public const ulong MaximumLifetimeMilliseconds=2592000000UL;
        public FileEnrollmentAction Action {get;private set;}public string Enrollment {get;private set;}public ulong Generation {get;private set;}
        public string PreviousEntry {get;private set;}public string PreviousRegistry {get;private set;}public string JournalHead {get;private set;}
        public ulong NotBefore {get;private set;}public ulong Expires {get;private set;}public EnrolledReadIntent Read {get;private set;}
        public FileEnrollmentIntent(FileEnrollmentAction action,string enrollment,ulong generation,string previousEntry,string previousRegistry,string head,ulong notBefore,ulong expires,EnrolledReadIntent read) {
            if(!Enum.IsDefined(typeof(FileEnrollmentAction),action) || generation<1 || generation>64 || read==null) throw new InvalidDataException("Closed file enrollment action, generation and exact file are required.");
            Wire.Bytes(enrollment,32,true);Wire.Bytes(previousRegistry,32,true);Wire.Bytes(head,32,true);Wire.Bytes(previousEntry,32,action!=FileEnrollmentAction.Create);
            if((action==FileEnrollmentAction.Create)!=(generation==1) || action==FileEnrollmentAction.Create && previousEntry!=new string('0',64)) throw new SecurityException("New enrollment must start at generation one without a predecessor.");
            if(action==FileEnrollmentAction.Revoke) {if(notBefore!=0 || expires!=0) throw new SecurityException("Revocation has no new or extended file-read lifetime.");}
            else if(generation>=64 || notBefore==0 || expires<=notBefore || expires>4102444800000UL || expires-notBefore>MaximumLifetimeMilliseconds) throw new SecurityException("Enrollment has a finite reviewed maximum30-day interval; generation64 is reserved for revocation.");
            Action=action;Enrollment=enrollment;Generation=generation;PreviousEntry=previousEntry;PreviousRegistry=previousRegistry;JournalHead=head;NotBefore=notBefore;Expires=expires;Read=read;
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-file-enrollment-intent-v1")) {
            writer.U8((byte)Action);writer.Fixed(Wire.Bytes(Enrollment,32,true),32);writer.U64(Generation);writer.Fixed(Wire.Bytes(PreviousEntry,32,Action!=FileEnrollmentAction.Create),32);writer.Fixed(Wire.Bytes(PreviousRegistry,32,true),32);writer.Fixed(Wire.Bytes(JournalHead,32,true),32);writer.U64(NotBefore);writer.U64(Expires);writer.Blob(Read.Encode(),2048);return writer.Bytes();
        }}
        public static FileEnrollmentIntent Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-file-enrollment-intent-v1")) {
            FileEnrollmentIntent result=new FileEnrollmentIntent((FileEnrollmentAction)reader.U8(),Wire.Hex(reader.Fixed(32)),reader.U64(),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),reader.U64(),reader.U64(),EnrolledReadIntent.Decode(reader.Blob(2048)));reader.End();if(!Wire.Equal(result.Encode(),bytes)) throw new SecurityException("Noncanonical enrollment control intent.");return result;
        }}
    }

    public sealed class FileEnrollmentRecord
    {
        public FileEnrollmentIntent Intent {get;private set;}public string ReviewSha256 {get;private set;}private readonly byte[] snapshot,proof,signature;
        public byte[] Snapshot {get{return (byte[])snapshot.Clone();}}
        public FileEnrollmentRecord(FileEnrollmentIntent intent,string review,byte[] snapshot,byte[] proof,byte[] signature) {
            if(intent==null) throw new ArgumentNullException("intent");Wire.Bytes(review,32,true);Intent=intent;ReviewSha256=review;this.snapshot=Wire.Copy(snapshot,intent.Action==FileEnrollmentAction.Revoke?0:1,4096);this.proof=Wire.Copy(proof,1,512);this.signature=Wire.Copy(signature,64,64);
            if(intent.Action==FileEnrollmentAction.Revoke) {if(snapshot.Length!=0) throw new SecurityException("Revocation cannot read or substitute a new source object.");}else intent.Read.ValidateSnapshot(snapshot);
            TimeAttestation.Decode(this.proof);if(Encode().Length>4096) throw new SecurityException("Complete enrollment event exceeds the existing journal payload bound.");
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-file-enrollment-record-v1")) {writer.Blob(Intent.Encode(),2048);writer.Fixed(Wire.Bytes(ReviewSha256,32,true),32);writer.Blob(snapshot,4096);writer.Blob(proof,512);writer.Fixed(signature,64);return writer.Bytes();}}
        public static FileEnrollmentRecord Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-file-enrollment-record-v1")) {FileEnrollmentRecord result=new FileEnrollmentRecord(FileEnrollmentIntent.Decode(reader.Blob(2048)),Wire.Hex(reader.Fixed(32)),reader.Blob(4096),reader.Blob(512),reader.Fixed(64));reader.End();if(!Wire.Equal(result.Encode(),bytes)) throw new SecurityException("Noncanonical enrollment record.");return result;}}
        internal void Envelope(AuthorityIdentity identity,JournalKind kind,string previousHead) {
            Intent.Read.Match(identity,identity.FirstAdminSid);
            if(Intent.JournalHead!=previousHead || (kind==JournalKind.FileEnrollmentRevoked)!=(Intent.Action==FileEnrollmentAction.Revoke) || kind!=JournalKind.FileEnrolled && kind!=JournalKind.FileEnrollmentRevoked) throw new SecurityException("File control event changed its exact journal parent or typed action.");
        }
        internal void VerifyTime(AuthorityIdentity current) {LiveUtcWindow.Validate(current,Wire.Hash(Intent.Encode()),Intent.Action==FileEnrollmentAction.Revoke?1:Intent.NotBefore,Intent.Action==FileEnrollmentAction.Revoke?4102444800000UL:Intent.Expires,TimeAttestation.Decode(proof),signature);}
        internal string TimeNonce {get{return TimeAttestation.Decode(proof).Nonce;}}
    }

    public sealed class EnrolledFileEntry
    {
        public FileEnrollmentIntent Policy {get;private set;}public string RecordSha256 {get;private set;}public bool Revoked {get;private set;}
        public ulong NotBefore {get;private set;}public ulong Expires {get;private set;}private readonly byte[] snapshot;
        public byte[] Snapshot {get{return (byte[])snapshot.Clone();}}public string ObjectSha256 {get{return Wire.Hash(snapshot);}}
        public void RequireSnapshot(byte[] actual) {if(Revoked || !Wire.Equal(snapshot,actual)) throw new SecurityException("Current file object/owner/ACL is not the active enrolled observation; exact explicit supersession is required.");}
        internal EnrolledFileEntry(FileEnrollmentRecord record,string sha,EnrolledFileEntry previous) {Policy=record.Intent;RecordSha256=sha;Revoked=record.Intent.Action==FileEnrollmentAction.Revoke;snapshot=Revoked?previous.Snapshot:record.Snapshot;NotBefore=Revoked?previous.NotBefore:record.Intent.NotBefore;Expires=Revoked?previous.Expires:record.Intent.Expires;}
    }

    // Rebuilt exclusively from the one protected signed journal. Public replay
    // metadata is not an authenticated session, current NV proof or file grant.
    public sealed class EnrolledFileRegistry
    {
        public const int MaximumIdentities=64,MaximumControls=256,MaximumGeneration=64;
        private readonly Dictionary<string,EnrolledFileEntry> entries=new Dictionary<string,EnrolledFileEntry>(StringComparer.Ordinal);private readonly HashSet<string> nonces=new HashSet<string>(StringComparer.Ordinal);
        public string SourceSha256 {get;private set;}public int ControlCount {get;private set;}public int ActiveCount {get;private set;}public int IdentityCount {get{return entries.Count;}}
        // One bounded uncertain-write recovery spare is funded per committed
        // Create. It is history-derived capacity, not permission to abort TPM.
        public int AbortReserveCredits {get;private set;}
        private EnrolledFileRegistry(AuthorityIdentity identity) {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-file-enrollment-genesis-v1")) {writer.Fixed(Wire.HashBytes(identity.Encode()),32);SourceSha256=Wire.Hash(writer.Bytes());}}
        public EnrolledFileEntry Find(string id) {Wire.Bytes(id,32,true);EnrolledFileEntry result;return entries.TryGetValue(id,out result)?result:null;}
        public void ValidateProposed(FileEnrollmentIntent intent,byte[] snapshot,string actualHead) {
            if(intent==null || intent.PreviousRegistry!=SourceSha256 || intent.JournalHead!=actualHead || ControlCount>=MaximumControls) throw new SecurityException("Enrollment registry generation/head/budget changed; no retry or authority adoption.");
            EnrolledFileEntry previous=Find(intent.Enrollment);
            if(intent.Action==FileEnrollmentAction.Create) {if(previous!=null || IdentityCount>=MaximumIdentities) throw new SecurityException("Enrollment identifier was used or lifetime identity budget exhausted.");}
            else if(previous==null || previous.Revoked || intent.Generation!=checked(previous.Policy.Generation+1) || intent.PreviousEntry!=previous.RecordSha256) throw new SecurityException("Enrollment predecessor is missing, revoked, stale, superseded or replayed.");
            if(intent.Action==FileEnrollmentAction.Revoke) {if(!Wire.Equal(intent.Read.Encode(),previous.Policy.Read.Encode()) || snapshot==null || snapshot.Length!=0) throw new SecurityException("Revocation changed the exact prior file or attempted source access.");}
            else {
                intent.Read.ValidateSnapshot(snapshot);int active=ActiveCount+(intent.Action==FileEnrollmentAction.Create?1:0);
                if(ControlCount+1+active>MaximumControls) throw new SecurityException("Control budget reserves one future revocation for every active enrollment.");
                if(previous!=null && Wire.Equal(intent.Read.Encode(),previous.Policy.Read.Encode()) && intent.NotBefore==previous.NotBefore && intent.Expires==previous.Expires && Wire.Equal(snapshot,previous.Snapshot)) throw new SecurityException("Unchanged enrollment supersession is not a new authorization.");
            }
        }
        internal void Apply(AuthorityIdentity current,JournalEntry entry,bool allowed) {
            FileEnrollmentRecord record=FileEnrollmentRecord.Decode(entry.Payload);record.Envelope(current,entry.Kind,entry.PreviousHead);if(!allowed || !nonces.Add(record.TimeNonce)) throw new SecurityException("File control crossed revoked/prepared authority or reused UTC freshness.");record.VerifyTime(current);
            ValidateProposed(record.Intent,record.Snapshot,entry.PreviousHead);EnrolledFileEntry prior=Find(record.Intent.Enrollment);EnrolledFileEntry next=new EnrolledFileEntry(record,entry.RecordSha256,prior);entries[record.Intent.Enrollment]=next;
            if(record.Intent.Action==FileEnrollmentAction.Create) {ActiveCount++;AbortReserveCredits++;}
            else if(record.Intent.Action==FileEnrollmentAction.Revoke) {ActiveCount--;AbortReserveCredits=Math.Min(AbortReserveCredits,ActiveCount);}
            ControlCount++;SourceSha256=entry.RecordSha256;
        }
        internal static EnrolledFileRegistry Replay(AuthorityIdentity identity,JournalHistory history,Action check) {
            if(identity==null || history==null || check==null) throw new ArgumentNullException("enrollment replay");EnrolledFileRegistry registry=new EnrolledFileRegistry(identity);bool present=false;
            foreach(JournalEntry entry in history.Entries) {check();if(entry.Kind==JournalKind.FileEnrolled || entry.Kind==JournalKind.FileEnrollmentRevoked) {present=true;break;}}if(!present) return registry;
            AuthorityIdentity current=identity;bool timeRevoked=false,trustPending=false,runtimePending=false;
            foreach(JournalEntry entry in history.Entries) {
                check();if(entry.Kind==JournalKind.TrustChanged) {TrustChange change=TrustRecord.Decode(entry.Payload).Change;
                    current=new AuthorityIdentity(identity.Domain,identity.Installation,identity.FirstAdminSid,identity.Environment,change.Publisher,change.Time,identity.AuthorityKey,identity.ServiceSha256,identity.WslSha256);
                    if(change.ChangesTime) timeRevoked=false;if(change.Action==4) timeRevoked=true;trustPending=false;
                } else if(entry.Kind==JournalKind.TrustPrepared) {TrustPreparation.Decode(entry.Payload);trustPending=true;}
                else if(entry.Kind==JournalKind.TrustCancelled) {TrustCancellation cancellation=TrustCancellation.Decode(entry.Payload);if(cancellation.ProposedTime) timeRevoked=true;trustPending=false;}
                else if(entry.Kind==JournalKind.RuntimePrepared) runtimePending=true;
                else if(entry.Kind==JournalKind.RuntimeActivated || entry.Kind==JournalKind.RuntimeCancelled) runtimePending=false;
                else if(entry.Kind==JournalKind.NvWriteAborted && registry.AbortReserveCredits>0) registry.AbortReserveCredits--;
                else if(entry.Kind==JournalKind.FileEnrolled || entry.Kind==JournalKind.FileEnrollmentRevoked) registry.Apply(current,entry,!timeRevoked && !trustPending && !runtimePending);
            }check();return registry;
        }
    }

    // Pure capacity DATA validation. The caller's existing genuine Admin,
    // current time, private-state and TPM dispatch guards remain mandatory.
    // No journal/event format or rollback authority is changed by this policy.
    public static class HostedJournalCapacity
    {
        public const ulong MaximumEvents=1024;
        public const long MaximumJournalBytes=8L*1024*1024;
        public const long ReservedEventBytes=8192;
        private static void Fits(ulong sequence,long bytes,int active,int credits) {
            if(active<0 || active>64 || credits<0 || credits>active || bytes<0 ||
                checked(sequence+(ulong)active+(ulong)credits)>MaximumEvents ||
                checked(bytes+checked((long)(active+credits)*ReservedEventBytes))>MaximumJournalBytes)
                throw new SecurityException("Shared hosted journal capacity is reserved for active file revocations and bounded uncertain-write recovery; no truncation, reset or extra epoch.");
        }
        private static bool FitsCurrent(ulong sequence,long bytes,int active,int credits) {
            try {Fits(sequence,bytes,active,credits);return true;}catch(SecurityException) {return false;}
        }
        public static void Require(AuthorityIdentity identity,JournalHistory history,JournalEntry candidate) {
            if(identity==null || history==null || candidate==null || history.FileEnrollments==null) throw new ArgumentNullException("capacity input");
            JournalEntry.Decode(identity,candidate.Bytes);
            if(candidate.Sequence!=checked(history.Sequence+1) || candidate.PreviousHead!=history.Head || candidate.PreviousRecord!=history.Record)
                throw new SecurityException("Capacity candidate is not the exact current one-event continuation.");
            long beforeBytes=0;foreach(JournalEntry entry in history.Entries) beforeBytes=checked(beforeBytes+entry.Bytes.Length);
            if(candidate.Bytes.Length>ReservedEventBytes) throw new SecurityException("Signed hosted event exceeds the closed reserved wire ceiling.");
            long nextBytes=checked(beforeBytes+candidate.Bytes.Length);
            int active=history.FileEnrollments.ActiveCount,credits=history.FileEnrollments.AbortReserveCredits;
            bool legacyDeficient=!FitsCurrent(history.Sequence,beforeBytes,active,credits);
            bool revoke=candidate.Kind==JournalKind.FileEnrollmentRevoked;
            bool abort=candidate.Kind==JournalKind.NvWriteAborted;
            if(legacyDeficient && !revoke && !abort)
                throw new SecurityException("Existing history lacks its derived file-policy capacity; read/inspect and a fitting reviewed terminal revoke/recovery only, never silent migration.");
            if(active>0 && credits==0 && !revoke && !abort)
                throw new SecurityException("Finite file-policy recovery spares are exhausted; only reviewed healthy revocation or a separately proved fitting recovery may continue.");
            if(candidate.Kind==JournalKind.FileEnrolled || revoke) {
                FileEnrollmentRecord record=FileEnrollmentRecord.Decode(candidate.Payload);record.Envelope(identity,candidate.Kind,history.Head);
                history.FileEnrollments.ValidateProposed(record.Intent,record.Snapshot,history.Head);
                if(record.Intent.Action==FileEnrollmentAction.Create) {active++;credits++;}
                else if(record.Intent.Action==FileEnrollmentAction.Revoke) {active--;credits=Math.Min(credits,active);}
            } else if(abort) {NvAbortEvent.Decode(identity,candidate.Payload).Matches(candidate);if(credits>0) credits--;}
            if(legacyDeficient && revoke) {
                // Old accepted bytes are never rewritten. A fitting terminal
                // revoke creates no promise and cannot increase an existing
                // deficit. Other legacy policies may still need a separately
                // reviewed future journal continuation; none is manufactured.
                Fits(candidate.Sequence,nextBytes,0,0);return;
            }
            Fits(candidate.Sequence,nextBytes,active,credits);
            // An attempted revoke has not retired its policy. Preserve the
            // alternative old-active tail if an actual funded abort is needed.
            // With no spare, a healthy terminal revoke is still allowed, but a
            // further uncertain write has no promised abort slot: it remains
            // globally fenced unless its separately reviewed abort actually fits.
            if(!abort && history.FileEnrollments.AbortReserveCredits>0)
                Fits(candidate.Sequence,checked(beforeBytes+ReservedEventBytes),history.FileEnrollments.ActiveCount,history.FileEnrollments.AbortReserveCredits-1);
        }
        public static T BeforeStage<T>(AuthorityIdentity identity,JournalHistory history,JournalEntry candidate,Func<T> stage) {
            if(stage==null) throw new ArgumentNullException("stage");Require(identity,history,candidate);return stage();
        }
        public static HostedPhysicalTail ProjectedPhysicalTail(AuthorityIdentity identity,JournalHistory history,JournalEntry candidate) {
            Require(identity,history,candidate);
            int active=history.FileEnrollments.ActiveCount,credits=history.FileEnrollments.AbortReserveCredits;
            if(candidate.Kind==JournalKind.FileEnrolled || candidate.Kind==JournalKind.FileEnrollmentRevoked) {
                FileEnrollmentAction action=FileEnrollmentRecord.Decode(candidate.Payload).Intent.Action;
                if(action==FileEnrollmentAction.Create) {active++;credits++;}
                else if(action==FileEnrollmentAction.Revoke) {active--;credits=Math.Min(credits,active);}
            } else if(candidate.Kind==JournalKind.NvWriteAborted && credits>0) credits--;
            return HostedPhysicalTail.ForEnrollments(active,credits);
        }
    }

    public sealed class PersistentReadSelection
    {
        public string Enrollment {get;private set;}public ulong Generation {get;private set;}public string EntrySha256 {get;private set;}public string RegistrySha256 {get;private set;}public string JournalHead {get;private set;}
        public PersistentReadSelection(string enrollment,ulong generation,string entry,string registry,string head) {Wire.Bytes(enrollment,32,true);Wire.Bytes(entry,32,true);Wire.Bytes(registry,32,true);Wire.Bytes(head,32,true);if(generation<1 || generation>=64) throw new SecurityException("Read selection must name one exact active enrollment generation.");Enrollment=enrollment;Generation=generation;EntrySha256=entry;RegistrySha256=registry;JournalHead=head;}
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-persistent-read-selection-v1")) {writer.Fixed(Wire.Bytes(Enrollment,32,true),32);writer.U64(Generation);writer.Fixed(Wire.Bytes(EntrySha256,32,true),32);writer.Fixed(Wire.Bytes(RegistrySha256,32,true),32);writer.Fixed(Wire.Bytes(JournalHead,32,true),32);return writer.Bytes();}}
        public static PersistentReadSelection Decode(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-persistent-read-selection-v1")) {PersistentReadSelection result=new PersistentReadSelection(Wire.Hex(reader.Fixed(32)),reader.U64(),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)));reader.End();return result;}}
        public EnrolledFileEntry Match(EnrolledFileRegistry registry,string actualHead,EnrolledReadIntent read) {
            EnrolledFileEntry entry=registry.Find(Enrollment);if(entry==null || entry.Revoked || entry.Policy.Generation!=Generation || entry.RecordSha256!=EntrySha256 || registry.SourceSha256!=RegistrySha256 || JournalHead!=actualHead || !Wire.Equal(entry.Policy.Read.Encode(),read.Encode())) throw new SecurityException("Selected persistent enrollment is revoked, superseded, missing, stale or bound to another exact file/current authority.");return entry;
        }
    }

    internal sealed class HostedEnrollmentInputs
    {
        internal readonly FileEnrollmentIntent Intent;
        internal HostedEnrollmentInputs(string hex) {if(hex==null || hex.Length<2 || hex.Length>4096 || hex.Length%2!=0) throw new SecurityException("Control intent must be exact bounded canonical hexadecimal.");Intent=FileEnrollmentIntent.Decode(Wire.Bytes(hex,hex.Length/2,true));}
        internal void Reviewed(byte[] exact) {using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-file-enrollment-review-v1")) {if(!Wire.Equal(reader.Blob(2048),Intent.Encode())) throw new SecurityException("Service changed the exact proposed enrollment policy.");byte[] snapshot=reader.Blob(4096);reader.End();if(Intent.Action==FileEnrollmentAction.Revoke) {if(snapshot.Length!=0) throw new SecurityException("Revocation cannot inspect a replacement file.");}else Intent.Read.ValidateSnapshot(snapshot);}}
        internal static int Describe(string[] arguments) {
            if(arguments.Length!=14) throw new InvalidDataException("enrollment-intent ACTION ID GENERATION PREVIOUS_ENTRY REGISTRY_SOURCE JOURNAL_HEAD NOT_BEFORE_MS EXPIRES_MS INSTALLATION ROOT RELATIVE_PATH EXACT_BYTES SHA256");
            FileEnrollmentAction action=arguments[1]=="create"?FileEnrollmentAction.Create:arguments[1]=="supersede"?FileEnrollmentAction.Supersede:arguments[1]=="revoke"?FileEnrollmentAction.Revoke:(FileEnrollmentAction)0;
            ulong generation=Number(arguments[3]),start=Number(arguments[7]),end=Number(arguments[8]);string[] read={"read-intent",arguments[9],arguments[10],arguments[11],arguments[12],arguments[13]};
            using(HostedReadInputs input=new HostedReadInputs(read,false)) {FileEnrollmentIntent intent=new FileEnrollmentIntent(action,arguments[2],generation,arguments[4],arguments[5],arguments[6],start,end,input.Intent);
                Console.WriteLine("Purpose: host-file-enrollment\nControl source SHA256 for separate native U review: "+Wire.Hash(intent.Encode())+"\nIntent hex: "+Wire.Hex(intent.Encode())+"\nNo source accessed, persistent enrollment committed, session admitted or authority granted.");return 0;}
        }
        internal static ulong Number(string value) {ulong result;if(!UInt64.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out result) || result.ToString(CultureInfo.InvariantCulture)!=value) throw new SecurityException("Canonical decimal value required.");return result;}
    }

    internal sealed class HostedPersistentReadInputs : IDisposable
    {
        internal readonly PersistentReadSelection Selection;internal readonly HostedReadInputs Read;
        internal HostedPersistentReadInputs(string[] arguments) {if(arguments.Length!=11) throw new InvalidDataException("read-persistent-file ID GENERATION ENTRY_SHA256 REGISTRY_SHA256 JOURNAL_HEAD INSTALLATION ROOT RELATIVE_PATH EXACT_BYTES SHA256");Selection=new PersistentReadSelection(arguments[1],HostedEnrollmentInputs.Number(arguments[2]),arguments[3],arguments[4],arguments[5]);string[] read={"read-enrolled-file",arguments[6],arguments[7],arguments[8],arguments[9],arguments[10]};Read=new HostedReadInputs(read,true);}
        internal void Reviewed(byte[] exact,string hash) {using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-persistent-read-review-v1")) {if(!Wire.Equal(reader.Blob(512),Selection.Encode())) throw new SecurityException("Persistent review changed exact original enrollment selection.");Read.Reviewed(reader.Blob(8192),hash);reader.End();}}
        internal void Complete(byte[] bytes) {using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-persistent-read-completed-v1")) {if(!Wire.Equal(reader.Blob(512),Selection.Encode())) throw new SecurityException("Persistent read receipt changed selected registry/current enrollment.");Read.Completed(reader.Blob(2048));reader.End();}}
        internal string Summary() {return "Selected persistent enrollment "+Selection.Enrollment+" generation "+Selection.Generation+" at exact current journal "+Selection.JournalHead+". "+Read.SummaryForPersistent();}
        public void Dispose() {Read.Dispose();}
    }

    internal static partial class HostedCoordinator
    {
        private static void NoUncertainFileAuthority(NativeAuthority authority) {if(authority.State.Exists("pending.bin") || authority.State.Exists("abort.intent")) throw new SecurityException("Uncertain protected write fences all new file access until exact existing journal recovery; no dispatch retry or old-enrollment fallback.");}
        private static LiveUtcWindow EnrollmentTime(PipeStream pipe,NativeAuthority authority,FileEnrollmentIntent intent,Action check) {
            return SourceTime(pipe,authority,intent.Read.Installation,Wire.Hash(intent.Encode()),intent.Action==FileEnrollmentAction.Revoke?1:intent.NotBefore,intent.Action==FileEnrollmentAction.Revoke?4102444800000UL:intent.Expires,check);
        }
        private static void ChangeFileEnrollment(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running) {
            FileEnrollmentIntent intent=FileEnrollmentIntent.Decode(request.Blob(2048));request.End();Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);intent.Read.Match(authority.Identity,actor.Sid);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());EnrolledFileRegistry registry=history.FileEnrollments;
                LiveUtcWindow utc=EnrollmentTime(pipe,authority,intent,original);Action check=delegate {original();authority.State.Check();utc.Check();};EnrolledReadSource source=null;
                try {
                    byte[] snapshot;if(intent.Action==FileEnrollmentAction.Revoke) snapshot=new byte[0];else {source=new EnrolledReadSource(intent.Read,actor.Token,check);snapshot=source.Snapshot();}registry.ValidateProposed(intent,snapshot,history.Head);
                    byte[] review;using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-file-enrollment-review-v1")) {exact.Blob(intent.Encode(),2048);exact.Blob(snapshot,4096);review=Review(pipe,"file-enrollment-change",exact.Bytes(),"Persistent first-Admin exact-file policy "+intent.Action+"\nEnrollment: "+intent.Enrollment+"; generation "+intent.Generation+"\nActual owner: "+actor.Sid+"\nExact source: "+intent.Read.Path+"\nExact bytes/SHA256: "+intent.Read.Bytes+" / "+intent.Read.Sha256+"\nEnrollment UTC half-open interval: ["+intent.NotBefore+", "+intent.Expires+") milliseconds; revocation grants no new interval.\nFresh independent UTC verification interval: ["+(intent.Action==FileEnrollmentAction.Revoke?1:intent.NotBefore)+", "+(intent.Action==FileEnrollmentAction.Revoke?4102444800000UL:intent.Expires)+"); nonce age<30seconds, full observed transit upper-bound projection; no local-clock fallback.\nExpected current protected journal head: "+history.Head+"\nRegistry source: "+registry.SourceSha256+"\nActual object fingerprint: "+(snapshot.Length==0?"not accessed (revocation)":Wire.Hash(snapshot))+"\nCaps:64 lifetime IDs,256 controls with future-revocation reservations,64 generations (64 revoke only),1MiB exact file,30-day maximum TTL. Every actual read still needs fresh30-second original-session review, current source/owner/ACL and protected UTC. No folder enumeration, source writes, Linux principal, ordinary-user mapping or automatic background ingestion.",check);}
                    if(source!=null) {byte[] capture=source.CaptureVerified();Array.Clear(capture,0,capture.Length);if(!Wire.Equal(snapshot,source.Snapshot())) throw new SecurityException("Exact reviewed enrollment object changed.");}
                    check();NoUncertainFileAuthority(authority);if(authority.Nv.ReadHead()!=history.Head) throw new SecurityException("Protected file-policy parent changed after confirmation.");
                    FileEnrollmentRecord record=new FileEnrollmentRecord(intent,Wire.Hash(review),snapshot,utc.Proof,utc.Signature);record.Envelope(authority.Identity,intent.Action==FileEnrollmentAction.Revoke?JournalKind.FileEnrollmentRevoked:JournalKind.FileEnrolled,history.Head);record.VerifyTime(authority.Trust.CurrentIdentity);
                    Action boundary=source==null?check:new Action(source.Check);authority.Journal.Append(intent.Action==FileEnrollmentAction.Revoke?JournalKind.FileEnrollmentRevoked:JournalKind.FileEnrolled,actor.Sid,record.Encode(),boundary);
                    JournalHistory completed=authority.Journal.Read(check);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());EnrolledFileEntry current=completed.FileEnrollments.Find(intent.Enrollment);
                    if(current==null || !Wire.Equal(current.Policy.Encode(),intent.Encode()) || current.Revoked!=(intent.Action==FileEnrollmentAction.Revoke)) throw new SecurityException("Protected journal did not reconstruct the exact file-policy completion.");
                    using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-file-enrollment-result-v1")) {result.Fixed(Wire.HashBytes(intent.Encode()),32);result.Fixed(Wire.Bytes(current.RecordSha256,32,true),32);result.Fixed(Wire.Bytes(completed.FileEnrollments.SourceSha256,32,true),32);result.Fixed(Wire.Bytes(completed.Head,32,true),32);result.U8(current.Revoked?(byte)1:(byte)0);result.U8(0);Reply(pipe,"file-enrollment-changed",result.Bytes(),check);}
                }finally {if(source!=null) source.Dispose();}
            }
        }
        private static void FileEnrollmentStatus(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running) {
            string id=Wire.Hex(request.Fixed(32));request.End();Stopwatch age=Stopwatch.StartNew();Action check=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,RuntimeAccess.Inspect,true)) {
                JournalHistory history=authority.Journal.Read(check);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());EnrolledFileRegistry registry=history.FileEnrollments;EnrolledFileEntry entry=registry.Find(id);
                using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-file-enrollment-status-v2")) {result.Fixed(Wire.Bytes(id,32,true),32);result.Fixed(Wire.Bytes(registry.SourceSha256,32,true),32);result.Fixed(Wire.Bytes(history.Head,32,true),32);result.U32((uint)registry.IdentityCount);result.U32((uint)registry.ActiveCount);result.U32((uint)registry.ControlCount);result.U32(64);result.U32(256);result.U32(64);result.U32(1048576);result.U64(FileEnrollmentIntent.MaximumLifetimeMilliseconds);result.U32(30);result.U32((uint)registry.AbortReserveCredits);result.U32((uint)HostedJournalCapacity.ReservedEventBytes);result.U8(1);result.U8(0);result.U8(0);result.U8(0);result.U8(entry==null?(byte)0:(byte)1);
                    if(entry!=null) {result.Blob(entry.Policy.Encode(),2048);result.Fixed(Wire.Bytes(entry.RecordSha256,32,true),32);result.Fixed(Wire.Bytes(entry.ObjectSha256,32,true),32);result.U64(entry.NotBefore);result.U64(entry.Expires);result.U8(entry.Revoked?(byte)1:(byte)0);}result.U8(authority.State.Exists("pending.bin") || authority.State.Exists("abort.intent")?(byte)1:(byte)0);result.U8(0);result.U8(0);Reply(pipe,"file-enrollment-status",result.Bytes(),check);}
            }
        }
        private static void ReadPersistentFile(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running) {
            PersistentReadSelection selected=PersistentReadSelection.Decode(request.Blob(512));EnrolledReadIntent intent=EnrolledReadIntent.Decode(request.Blob(2048));request.End();Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);authority.State.RequireReadableTail();intent.Match(authority.Identity,actor.Sid);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());EnrolledFileEntry entry=selected.Match(history.FileEnrollments,history.Head,intent);
                LiveUtcWindow utc=SourceTime(pipe,authority,intent.Installation,Wire.Hash(intent.Encode()),entry.NotBefore,entry.Expires,original);Action check=delegate {original();authority.State.Check();NoUncertainFileAuthority(authority);utc.Check();if(authority.Nv.ReadHead()!=history.Head) throw new SecurityException("Persistent enrollment authority changed during read.");original();};
                using(EnrolledReadSource source=new EnrolledReadSource(intent,actor.Token,check)) {
                    byte[] snapshot=source.Snapshot();entry.RequireSnapshot(snapshot);byte[] review;
                    using(Wire.Writer originalReview=new Wire.Writer("luma-windows-hosted-read-review-v1")) {originalReview.Blob(intent.Encode(),2048);originalReview.Blob(snapshot,4096);using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-persistent-read-review-v1")) {exact.Blob(selected.Encode(),512);exact.Blob(originalReview.Bytes(),8192);
                        review=Review(pipe,"read-persistent-file",exact.Bytes(),"Fresh30-second read of current nonrevoked persistent enrollment "+selected.Enrollment+" generation "+selected.Generation+"\nActual owner: "+actor.Sid+"\nExact source: "+intent.Path+"\nExact bytes/SHA256: "+intent.Bytes+" / "+intent.Sha256+"\nCurrent journal: "+history.Head+"\nEnrollment UTC interval: ["+entry.NotBefore+", "+entry.Expires+") milliseconds\nNo new enrollment, publication, write, folder enumeration, ordinary-user/Linux principal or automatic ingestion. Cancellation/refusal may leave partial bytes delivered only to this original client.",check);}}
                    EnrolledReadDelivery delivery=new EnrolledReadDelivery(intent,Wire.Hash(review),Wire.Hash(snapshot));delivery.Begin(Wire.Hash(intent.Encode()),Wire.Hash(source.Snapshot()));byte[] content=source.CaptureVerified();
                    try {while(delivery.Delivered<content.Length) {source.Check();byte[] chunk=delivery.Chunk(content,(int)delivery.Delivered);try {Reply(pipe,"persistent-read-chunk",chunk,source.Check);}finally {Array.Clear(chunk,0,chunk.Length);}byte[] ack=HostedPipe.Read(pipe,source.Check,Standard);try {source.Check();delivery.Acknowledge(ack,content);}finally {Array.Clear(ack,0,ack.Length);}}
                        byte[] after=source.CaptureVerified();try {if(!Wire.Equal(content,after)) throw new SecurityException("Enrolled source changed after delivery; no complete persistent-read receipt.");}finally {Array.Clear(after,0,after.Length);}
                        source.Check();using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-persistent-read-completed-v1")) {result.Blob(selected.Encode(),512);result.Blob(delivery.Complete(),2048);Reply(pipe,"persistent-read-completed",result.Bytes(),source.Check);}
                    }finally {Array.Clear(content,0,content.Length);}
                }
            }
        }
    }
}
