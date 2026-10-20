using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace Luma.Windows.Hosted
{
    // Commission intent is durable before creating a named machine key. It
    // contains public anchors only and cannot authorize arbitrary signing.
    public sealed class CommissionIntent
    {
        public string Domain {get;private set;}
        public string Installation {get;private set;}
        public string Administrator {get;private set;}
        public string Environment {get;private set;}
        public string ServiceSha256 {get;private set;}
        public string WslSha256 {get;private set;}
        public string TimeEndpoint {get;private set;}
        public RuntimeBundle Baseline {get;private set;}
        private readonly byte[] release,time;
        public byte[] ReleaseKey {get{return (byte[])release.Clone();}}public byte[] TimeKey {get{return (byte[])time.Clone();}}
        public CommissionIntent(string domain,string installation,string administrator,string environment,byte[] release,byte[] time,string service,string wsl,string endpoint,RuntimeBundle baseline)
        {
            PlatformCustodyProtocol.Index(domain);Wire.Bytes(installation,32,true);Wire.Sid(administrator);Wire.Environment(environment);
            Wire.Bytes(service,32,true);Wire.Bytes(wsl,32,true);this.release=AuthorityIdentity.Public(release);this.time=AuthorityIdentity.Public(time);
            if(Wire.Equal(this.release,this.time)) throw new SecurityException("Release and protected UTC authorities must be independent.");
            if(baseline==null || baseline.ServiceSha256!=service) throw new SecurityException("Commissioning requires the explicit complete EXE/DLL runtime baseline, not a guessed legacy default.");Baseline=baseline;
            Domain=domain;Installation=installation;Administrator=administrator;Environment=environment;ServiceSha256=service;WslSha256=wsl;TimeEndpoint=HostedTimeEndpoint.Validate(endpoint);
        }
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-commission-intent-v2")) {
                writer.Text(Domain,32);writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.Text(Administrator,184);writer.Text(Environment,10);
                writer.Fixed(release,72);writer.Fixed(time,72);writer.Fixed(Wire.Bytes(ServiceSha256,32,true),32);writer.Fixed(Wire.Bytes(WslSha256,32,true),32);writer.Text(TimeEndpoint,2048);writer.Blob(Baseline.Encode(),1024);return writer.Bytes();
            }
        }
        public static CommissionIntent Decode(byte[] bytes)
        {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-commission-intent-v2")) {
                CommissionIntent result=new CommissionIntent(reader.Text(32),Wire.Hex(reader.Fixed(32)),reader.Text(184),reader.Text(10),reader.Fixed(72),reader.Fixed(72),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),reader.Text(2048),RuntimeBundle.Decode(reader.Blob(1024)));
                reader.End();if(!Wire.Equal(result.Encode(),bytes)) throw new SecurityException("Noncanonical protected commissioning intent.");return result;
            }
        }
        internal AuthorityIdentity Identity(byte[] key)
        {return new AuthorityIdentity(Domain,Installation,Administrator,Environment,release,time,key,ServiceSha256,WslSha256);}
        internal void Matches(AuthorityIdentity identity)
        {
            if(!Wire.Equal(Identity(identity.AuthorityKey).Encode(),identity.Encode())) throw new SecurityException("Pending identity differs from the protected intent.");
        }
        public byte[] GenesisPayload(AuthorityIdentity identity)
        {
            Matches(identity);using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-commission-genesis-v1")) {
                writer.Blob(identity.Encode(),4096);writer.Fixed(Wire.HashBytes(Encode()),32);return writer.Bytes();
            }
        }
        public byte[] RecoveredGenesisPayload(AuthorityIdentity identity,NvAbortEvent recovery)
        {
            if(recovery.Abandoned.Sequence!=1 || recovery.Abandoned.PreviousHead!=new string('0',64)) throw new SecurityException("Genesis recovery must replace the exact zero-head first event.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-commission-genesis-recovered-v1")) {writer.Blob(GenesisPayload(identity),4096);writer.Blob(recovery.Encode(),2048);return writer.Bytes();}
        }
        public NvAbortEvent RecoveredGenesis(AuthorityIdentity identity,byte[] payload)
        {
            using(Wire.Reader reader=new Wire.Reader(payload,"luma-windows-hosted-commission-genesis-recovered-v1")) {
                if(!Wire.Equal(reader.Blob(4096),GenesisPayload(identity))) throw new SecurityException("Recovered genesis changed the protected commissioning anchors.");
                NvAbortEvent recovery=NvAbortEvent.Decode(identity,reader.Blob(2048));reader.End();
                if(recovery.Abandoned.Sequence!=1 || recovery.Abandoned.PreviousHead!=new string('0',64)) throw new SecurityException("Recovered genesis ticket differs from the first event.");return recovery;
            }
        }
        public void ValidateGenesis(AuthorityIdentity identity,byte[] payload)
        {if(!Wire.Equal(payload,GenesisPayload(identity))) RecoveredGenesis(identity,payload);}
    }

    internal sealed class NativeAuthority : IDisposable
    {
        internal readonly PrivateState State;internal readonly AuthorityIdentity Identity;internal readonly HardwareKey Key;
        internal readonly FixedNvAuthority Nv;internal readonly DurableJournal Journal;internal readonly CommissionIntent Intent;internal readonly HostedTrustState Trust;internal readonly HostedRuntimeState Runtime;
        private readonly InstalledRuntimeLease runtimeLease;
        internal NativeAuthority(string domain,HostedActor actor)
            :this(domain,actor,RuntimeAccess.Standard) {}
        internal NativeAuthority(string domain,HostedActor actor,RuntimeAccess runtimeAccess)
            :this(domain,actor,runtimeAccess,false) {}
        internal NativeAuthority(string domain,HostedActor actor,RuntimeAccess runtimeAccess,bool computeRecovery)
        {
            State=PrivateState.OpenFixed(domain,false);
            try {
                Identity=AuthorityIdentity.Decode(State.Read("identity.bin",1,4096));if(Identity.Domain!=domain) throw new SecurityException("Private authority domain differs.");
                actor.RequireAdmin(Identity.FirstAdminSid);
                Intent=CommissionIntent.Decode(State.Read("commission.intent",1,4096));Intent.Matches(Identity);
                Key=HardwareKey.Open(Identity);Nv=new FixedNvAuthority(Identity,Key);Journal=new DurableJournal(State,Identity,Key,Nv);
                if(State.Exists("identity.pending")) throw new SecurityException("A published authority has an unexplained pending identity.");
                JournalHistory history=Journal.Read(delegate {actor.RequireAdmin(Identity.FirstAdminSid);State.Check();});if(history.Entries.Length<1) throw new SecurityException("Commissioning genesis is absent.");
                DeploymentHistory deployment=DeploymentHistory.Replay(history,delegate {actor.RequireAdmin(Identity.FirstAdminSid);State.Check();});
                if(deployment.Pending!=null && deployment.Pending.Purpose>=3 && !computeRecovery)
                    throw new SecurityException("Unresolved compute or inference generation fences all new effects and private reads; inspect or explicitly recover the exact original controller, never replay work.");
                Intent.ValidateGenesis(Identity,history.Entries[0].Payload);
                Trust=HostedTrustState.Replay(Identity,Intent,history,delegate {actor.RequireAdmin(Identity.FirstAdminSid);State.Check();});
                Runtime=HostedRuntimeState.Replay(Identity,Intent.Baseline,Trust,history,delegate {actor.RequireAdmin(Identity.FirstAdminSid);State.Check();});
                HostedRuntimeFiles.CheckRunning(Runtime,runtimeAccess,delegate {actor.RequireAdmin(Identity.FirstAdminSid);State.Check();});
                string runningSlot=String.Equals(HostedRuntimeFiles.Running,HostedRuntimeFiles.Executable(Runtime.Slot),StringComparison.OrdinalIgnoreCase)?Runtime.Slot:Runtime.Pending.Slot;
                runtimeLease=new InstalledRuntimeLease(runningSlot,runningSlot==Runtime.Slot?Runtime.Current:Runtime.Pending.Update.Bundle,delegate {actor.RequireAdmin(Identity.FirstAdminSid);});State.AttachRuntimeIntegrity(runtimeLease.Check);
            } catch {Dispose();throw;}
        }
        public void Dispose() {if(Nv!=null) Nv.Dispose();if(Key!=null) Key.Dispose();if(State!=null) State.Dispose();if(runtimeLease!=null) runtimeLease.Dispose();}
    }

    internal static partial class HostedCoordinator
    {
        private static readonly TimeSpan Standard=TimeSpan.FromSeconds(30);
        internal static string FileHash(string path)
        {
            using(InstalledInputLease lease=InstalledInputLease.Acquire(path)) {
                if(lease.Length<64 || lease.Length>128*1024*1024) throw new SecurityException("Fixed native runtime image size differs.");
                lease.Check();string digest;using(SHA256 hash=SHA256.Create()) digest=Wire.Hex(hash.ComputeHash(lease.Rewind()));lease.Check();return digest;
            }
        }
        private static void CheckCommissionRuntime(CommissionIntent intent,Action check)
        {
            check();FixedServiceIdentity.Require();if(!String.Equals(HostedRuntimeFiles.Running,HostedRuntimeFiles.Executable(""),StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Initial commissioning must use the exact fixed installed runtime path.");
            HostedRuntimeFiles.RequireLoadedOrigins("");HostedRuntimeFiles.Require("",intent.Baseline,check);
            // This ceremony never launches WSL. If Microsoft updates wsl.exe
            // during an interrupted commission, the original pin remains in
            // genesis and all effects refuse until a signed runtime migration.
        }
        private static Action Live(HostedActor actor,Action running,Stopwatch age)
        {return delegate {running();actor.Check();if(age.Elapsed>=Standard) throw new SecurityException("The exact standard Admin action expired; no extended-session fallback.");};}
        internal static void Reply(PipeStream pipe,string kind,byte[] payload,Action check)
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-response-v1")) {writer.Text(kind,32);writer.Blob(payload,60000);HostedPipe.Write(pipe,writer.Bytes(),check,Standard);}
        }
        private static byte[] Review(PipeStream pipe,string action,byte[] exact,string detail,Action check)
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-reviewed-action-v1")) {
                writer.Text(action,32);writer.Fixed(Wire.Random(32),32);writer.Blob(exact,8192);writer.Text(detail,16000);byte[] review=writer.Bytes();
                Reply(pipe,"review",review,check);byte[] confirmation=HostedPipe.Read(pipe,check,Standard);
                try {using(Wire.Reader reader=new Wire.Reader(confirmation,"luma-windows-hosted-confirm-v1")) {
                    if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(review)) throw new SecurityException("Original Admin did not confirm this exact fresh review.");reader.End();
                }} finally {Array.Clear(confirmation,0,confirmation.Length);}check();return review;
            }
        }
        private static string Describe(CommissionIntent intent,byte[] bytes)
        {
            return "Action: commission separate "+intent.Domain+" authority\nEnvironment: "+intent.Environment+"\nActual first Admin: "+intent.Administrator+
                "\nInstallation: "+intent.Installation+"\nIntent SHA256: "+Wire.Hash(bytes)+"\nPublisher key SHA256: "+Wire.Hash(intent.ReleaseKey)+"\nIndependent UTC key SHA256: "+Wire.Hash(intent.TimeKey)+"\nProtected UTC endpoint: "+intent.TimeEndpoint+"\nFull four-file runtime bundle SHA256: "+intent.Baseline.Sha256+"\nService image SHA256: "+intent.ServiceSha256+"\nWindows WSL image SHA256: "+intent.WslSha256+
                "\nCreates/resumes only the reviewed named TPM machine key and fixed W/X NV index. Never clears TPM, replaces an occupied unrelated slot, exports private keys, or activates a distribution.";
        }
        private static void Commission(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,bool resume)
        {
            string domain=request.Text(32);PlatformCustodyProtocol.Index(domain);actor.RequireAdmin(null);
            CommissionIntent intent;byte[] bytes;Stopwatch age=Stopwatch.StartNew();Action check=Live(actor,running,age);
            if(resume) {
                request.End();using(PrivateState state=PrivateState.OpenFixed(domain,false)) {
                    if(state.Exists("identity.bin")) throw new SecurityException("Authority is already commissioned; use explicit journal recovery, not commissioning.");
                    bytes=state.Read("commission.intent",1,4096);intent=CommissionIntent.Decode(bytes);actor.RequireAdmin(intent.Administrator);
                    if(intent.Domain!=domain) throw new SecurityException("Pending commission domain differs.");CheckCommissionRuntime(intent,check);
                }
            } else {
                string environment=request.Text(10);byte[] release=request.Fixed(72),time=request.Fixed(72);string endpoint=request.Text(2048);request.End();
                intent=new CommissionIntent(domain,Wire.Hex(Wire.Random(32)),actor.Sid,environment,release,time,
                    FileHash(Process.GetCurrentProcess().MainModule.FileName),FileHash(Path.Combine(System.Environment.SystemDirectory,"wsl.exe")),endpoint,HostedRuntimeFiles.Capture("",check));bytes=intent.Encode();
            }
            CheckCommissionRuntime(intent,check);Review(pipe,resume?"commission-resume":"commission",bytes,Describe(intent,bytes),check);
            byte[] secretFrame=HostedPipe.Read(pipe,check,Standard),ownerAuth=null;
            try {
                using(Wire.Reader secret=new Wire.Reader(secretFrame,"luma-windows-hosted-owner-authorization-v1")) {ownerAuth=secret.Blob(64);secret.End();if(ownerAuth.Length<1) throw new SecurityException("Existing owner hierarchy authorization is explicit and nonempty.");}
                using(PrivateState state=PrivateState.OpenFixed(domain,!resume)) {
                    if(state.Exists("identity.bin")) throw new SecurityException("Cannot overwrite an existing commissioned identity.");
                    if(resume) {if(!Wire.Equal(state.Read("commission.intent",1,4096),bytes)) throw new SecurityException("Protected intent changed after review.");}
                    else {
                        string[] leaves=state.Leaves();if(leaves.Length!=1 || leaves[0]!="authority.lock") throw new SecurityException("Fresh commissioning refuses all pre-existing authority data.");
                        check();state.WriteNew("commission.intent",bytes);
                    }
                    CheckCommissionRuntime(intent,check);check();
                    using(InstalledRuntimeLease baseline=new InstalledRuntimeLease("",intent.Baseline,check))
                    using(HardwareKey key=resume?HardwareKey.ResumePending(domain,intent.Installation):HardwareKey.Create(domain,intent.Installation)) {
                        state.AttachRuntimeIntegrity(baseline.Check);
                        AuthorityIdentity identity=intent.Identity(key.PublicBlob);byte[] identityBytes=identity.Encode();
                        if(state.Exists("identity.pending")) {if(!Wire.Equal(identityBytes,state.Read("identity.pending",1,4096))) throw new SecurityException("Pending identity or actual CNG machine key changed.");}
                        else {check();state.WriteNew("identity.pending",identityBytes);}
                        byte[] genesisPayload=intent.GenesisPayload(identity);JournalEntry genesis=JournalEntry.Prepare(identity,1,JournalKind.Commission,new string('0',64),new string('0',64),actor.Sid,genesisPayload);
                        using(FixedNvAuthority nv=new FixedNvAuthority(identity,key)) {
                            DurableJournal journal=new DurableJournal(state,identity,key,nv);DispatchTicket dispatch=null;
                            if(state.Exists("pending.bin")) {
                                JournalEntry pending=JournalEntry.Decode(identity,state.Read("pending.bin",1,20000));
                                if(pending.Sequence!=1 || pending.Kind!=JournalKind.Commission) throw new SecurityException("Pending genesis does not match this reviewed identity.");intent.ValidateGenesis(identity,pending.Payload);
                            } else if(!state.Exists("record-0001.bin")) {
                                check();genesis=genesis.Signed(identity,key.Sign(genesis.SigningInput));dispatch=journal.PrepareDispatch(genesis,check);check();state.WriteNew("pending.bin",genesis.Bytes);
                            }
                            check();nv.EnsureDefinedForPendingGenesis(ownerAuth);
                            if(dispatch!=null) journal.DispatchFirst(genesis,dispatch,check);
                            JournalHistory history=journal.Recover(check);
                            if(history.Sequence!=1 || history.Last.Kind!=JournalKind.Commission) throw new SecurityException("Actual commissioned hardware history is not the exact genesis.");intent.ValidateGenesis(identity,history.Last.Payload);
                            check();state.Publish("identity.pending","identity.bin");history.Reconcile(identity,null,nv.ReadHead());
                            Reply(pipe,"commissioned",identityBytes,check);
                        }
                    }
                }
            } finally {Array.Clear(secretFrame,0,secretFrame.Length);if(ownerAuth!=null) Array.Clear(ownerAuth,0,ownerAuth.Length);}
        }
        private static void StatusOrRecover(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,bool recover)
        {
            string domain=request.Text(32);request.End();Stopwatch age=Stopwatch.StartNew();Action check=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority(domain,actor,RuntimeAccess.Inspect,true)) {
                JournalHistory history=authority.Journal.Read(check);string observed=authority.Nv.ReadHead();byte[] pending=authority.State.Exists("pending.bin")?authority.State.Read("pending.bin",1,20000):null;
                RecoveryPhase phase=history.Reconcile(authority.Identity,pending,observed);
                if(recover) {
                    using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-journal-recovery-review-v1")) {
                        exact.Fixed(Wire.HashBytes(authority.Identity.Encode()),32);exact.Fixed(Wire.Bytes(observed,32,history.Sequence!=0),32);exact.U64(history.Sequence);
                        exact.U8((byte)phase);exact.Blob(pending==null?new byte[0]:Wire.HashBytes(pending),32);
                        Review(pipe,"recover",exact.Bytes(),"Recover only the reviewed signed journal write: "+phase+". Never reset, discard, recreate, replay a guest effect, or adopt missing history.",check);
                    }
                    if(authority.Nv.ReadHead()!=observed || (pending==null)!=(!authority.State.Exists("pending.bin")) ||
                        (pending!=null && !Wire.Equal(pending,authority.State.Read("pending.bin",1,20000)))) throw new SecurityException("Recovery inputs changed after confirmation.");
                    history=authority.Journal.Recover(check);phase=RecoveryPhase.Clean;
                }
                DeploymentHistory deployment=DeploymentHistory.Replay(history,check);
                using(Wire.Writer output=new Wire.Writer("luma-windows-hosted-status-v4")) {
                    output.Blob(authority.Identity.Encode(),4096);output.U64(history.Sequence);output.Fixed(Wire.Bytes(recover?history.Head:observed,32,true),32);output.U8((byte)phase);
                    output.U8(deployment.Active==null?(byte)0:(byte)1);output.U8(0);output.U8(0);
                    output.Text(deployment.Pending==null?"":deployment.Pending.Generation,64);output.U8(deployment.Pending==null?(byte)0:deployment.Pending.Purpose);
                    output.U32(deployment.Worker==null?0:deployment.Worker.Controller);output.U64(deployment.Worker==null?0:deployment.Worker.ControllerCreation);
                    HostedTrustState trust=HostedTrustState.Replay(authority.Identity,authority.Intent,history,check);output.U64(trust.Generation);output.Fixed(Wire.Bytes(trust.SourceSha256,32,true),32);
                    output.Fixed(trust.CurrentIdentity.ReleaseKey,72);output.Fixed(trust.CurrentIdentity.TimeKey,72);output.Text(trust.Endpoint,2048);output.U8(trust.PublisherRevoked?(byte)1:(byte)0);output.U8(trust.TimeRevoked?(byte)1:(byte)0);
                    output.Text(trust.Pending==null?"":Wire.Hash(trust.Pending.Change.Encode()),64);
                    HostedRuntimeState runtime=HostedRuntimeState.Replay(authority.Identity,authority.Intent.Baseline,trust,history,check);
                    output.U64(runtime.Generation);output.Fixed(Wire.Bytes(runtime.SourceSha256,32,true),32);output.Fixed(Wire.Bytes(runtime.Current.Sha256,32,true),32);output.Fixed(Wire.Bytes(runtime.WslSha256,32,true),32);
                    output.Text(runtime.Slot,64);output.Text(runtime.Pending==null?"":Wire.Hash(runtime.Pending.Update.Encode()),64);output.Text(runtime.Pending==null?"":runtime.Pending.Slot,64);Reply(pipe,"status",output.Bytes(),check);
                }
            }
        }
        private static void AbortJournal(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running)
        {
            string domain=request.Text(32);request.End();Stopwatch age=Stopwatch.StartNew();Action check=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority(domain,actor,RuntimeAccess.Inspect,true)) {
                byte[] exact=authority.Journal.ReviewAbort(check);
                Review(pipe,"recover-abort",exact,"Abort only the exact uncommitted NV event after independently observed host boot change AND TPM reset count advancement. Never reissue the old extend, reset custody, delete evidence, replay a guest effect or claim resource completion.",check);
                JournalHistory history=authority.Journal.Abort(exact,check);
                using(Wire.Writer output=new Wire.Writer("luma-windows-hosted-nv-aborted-v1")) {
                    output.Text(domain,32);output.U64(history.Sequence);output.Fixed(Wire.Bytes(history.Head,32,true),32);output.U8(0);Reply(pipe,"nv-aborted",output.Bytes(),check);
                }
            }
        }
        private static void AbortCommission(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running)
        {
            string domain=request.Text(32);request.End();Stopwatch age=Stopwatch.StartNew();Action check=Live(actor,running,age);
            using(PrivateState state=PrivateState.OpenFixed(domain,false)) {
                if(state.Exists("identity.bin")) throw new SecurityException("Published authority must use post-commission recover-abort.");
                CommissionIntent intent=CommissionIntent.Decode(state.Read("commission.intent",1,4096));AuthorityIdentity identity=AuthorityIdentity.Decode(state.Read("identity.pending",1,4096));
                intent.Matches(identity);actor.RequireAdmin(identity.FirstAdminSid);CheckCommissionRuntime(intent,check);
                using(InstalledRuntimeLease baseline=new InstalledRuntimeLease("",intent.Baseline,check))
                using(HardwareKey key=HardwareKey.Open(identity)) using(FixedNvAuthority nv=new FixedNvAuthority(identity,key)) {
                    state.AttachRuntimeIntegrity(baseline.Check);
                    DurableJournal journal=new DurableJournal(state,identity,key,nv);byte[] exact=journal.ReviewAbort(check,true);
                    Review(pipe,"commission-abort",exact,"Replace only an uncertain zero-head genesis after independently observed host boot change AND strictly advanced TPM reset count. Preserve original key, installation, anchors, endpoint, NV object and signed old intent. No clear, reset, replacement custody or old-extend retry.",check);
                    JournalHistory history=journal.Abort(exact,check,true);
                    if(history.Sequence!=1 || history.Last.Kind!=JournalKind.Commission) throw new SecurityException("Recovered first event is not commissioned genesis.");intent.ValidateGenesis(identity,history.Last.Payload);
                    check();state.Publish("identity.pending","identity.bin");history.Reconcile(identity,null,nv.ReadHead());Reply(pipe,"commissioned",identity.Encode(),check);
                }
            }
        }
        private static void ReleaseReview(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running)
        {
            byte[] description=request.Blob(60000),signature=request.Fixed(64);request.End();ReleaseDescriptor release=ReleaseDescriptor.Decode(description);
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());
                release.Verify(authority.Trust.ForRelease(),signature);HostedReleaseLease time=new HostedReleaseLease(pipe,authority,release,signature,original);time.Check();
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-release-review-v1")) {
                    exact.Fixed(Wire.HashBytes(description),32);exact.Fixed(signature,64);exact.Fixed(Wire.Bytes(history.Head,32,true),32);
                    Review(pipe,"release-review",exact.Bytes(),"Verify publisher-signed release "+release.Sequence+" in environment "+release.Environment+
                        "\nDescriptor SHA256: "+Wire.Hash(description)+"\nRootfs SHA256: "+release.RootfsSha256+"\nArchive bytes: "+release.ArchiveBytes+
                        "\nIndependent nonce-signed protected UTC verified through the commissioned endpoint. This command imports nothing, grants no execution authority and does not qualify a guest.",time.CheckObserved);
                }
                time.Check();if(authority.Nv.ReadHead()!=history.Head) throw new SecurityException("Authority changed during exact release review.");
                using(Wire.Writer output=new Wire.Writer("luma-windows-hosted-reviewed-release-v1")) {
                    output.Fixed(Wire.HashBytes(description),32);output.U64(release.Sequence);output.U8(0);output.U8(0);output.U8(0);Reply(pipe,"release-reviewed",output.Bytes(),time.Check);
                }
            }
        }
        internal static void Handle(NamedPipeServerStream pipe,Action running)
        {
            // Read one exact hello before impersonation so the kernel has an
            // actual client message to associate with RunAsClient.
            byte[] hello=HostedPipe.Read(pipe,running,Standard);
            using(Wire.Reader reader=new Wire.Reader(hello,"luma-windows-hosted-hello-v1")) {if(reader.U32()!=1) throw new InvalidDataException("Hosted protocol version differs.");reader.End();}
            using(HostedActor actor=HostedActor.Capture(pipe)) {
                actor.RequireAdmin(null);byte[] frame=HostedPipe.Read(pipe,actor.Check,Standard);
                try {using(Wire.Reader request=new Wire.Reader(frame,"luma-windows-hosted-request-v1")) {
                    string command=request.Text(32);
                    switch(command) {
                        case "commission":Commission(pipe,actor,request,running,false);break;
                        case "commission-resume":Commission(pipe,actor,request,running,true);break;
                        case "commission-abort":AbortCommission(pipe,actor,request,running);break;
                        case "status":StatusOrRecover(pipe,actor,request,running,false);break;
                        case "recover":StatusOrRecover(pipe,actor,request,running,true);break;
                        case "recover-abort":AbortJournal(pipe,actor,request,running);break;
                        case "release-review":ReleaseReview(pipe,actor,request,running);break;
                        case "import":ImportOrActivate(pipe,actor,request,running,false);break;
                        case "activate":ImportOrActivate(pipe,actor,request,running,true);break;
                        case "reconcile":ReconcileDeployment(pipe,actor,request,running,false);break;
                        case "abandon":ReconcileDeployment(pipe,actor,request,running,true);break;
                        case "trust":ChangeTrust(pipe,actor,request,running,"trust");break;
                        case "trust-prepare":ChangeTrust(pipe,actor,request,running,"trust-prepare");break;
                        case "trust-finalize":ChangeTrust(pipe,actor,request,running,"trust-finalize");break;
                        case "trust-cancel":ChangeTrust(pipe,actor,request,running,"trust-cancel");break;
                        case "trust-quarantine":ChangeTrust(pipe,actor,request,running,"trust-quarantine");break;
                        case "runtime-prepare":RuntimeCommand(pipe,actor,request,running,"runtime-prepare");break;
                        case "runtime-switch":RuntimeCommand(pipe,actor,request,running,"runtime-switch");break;
                        case "runtime-finalize":RuntimeCommand(pipe,actor,request,running,"runtime-finalize");break;
                        case "runtime-cancel":RuntimeCommand(pipe,actor,request,running,"runtime-cancel");break;
                        case "read-enrolled-file":ReadEnrolledFile(pipe,actor,request,running);break;
                        case "file-enrollment-change":ChangeFileEnrollment(pipe,actor,request,running);break;
                        case "file-enrollment-status":FileEnrollmentStatus(pipe,actor,request,running);break;
                        case "read-persistent-file":ReadPersistentFile(pipe,actor,request,running);break;
                        case "compute":ComputeActive(pipe,actor,request,running);break;
                        case "compute-recover":RecoverCompute(pipe,actor,request,running);break;
                        case "infer":InferenceActive(pipe,actor,request,running);break;
                        case "infer-recover":RecoverInference(pipe,actor,request,running);break;
                        default:throw new InvalidDataException("Hosted service command is not in the closed protocol.");
                    }
                }} finally {Array.Clear(frame,0,frame.Length);}
            }
        }
    }

    // Lifecycle only: delegates cannot grant identity, custody or effects. The
    // installed service binds reporting to SCM and fatal termination to its own
    // process. Software tests exercise the same gates without installing SCM.
    internal sealed class HostedServiceWorker
    {
        private readonly object gate=new object();private readonly Action serve;private readonly Action<int> reportFailure;private readonly Action<string> terminate;
        private volatile bool stopping;private Thread thread;private IDisposable active;
        internal HostedServiceWorker(Action serve,Action<int> reportFailure,Action<string> terminate) {
            if(serve==null || reportFailure==null || terminate==null) throw new ArgumentNullException("lifecycle");this.serve=serve;this.reportFailure=reportFailure;this.terminate=terminate;
        }
        internal bool Stopping {get{return stopping;}}
        internal void Start() {
            lock(gate) {
                if(thread!=null || stopping) throw new InvalidOperationException("Service worker cannot be started or restarted twice.");
                thread=new Thread(Run);thread.IsBackground=true;
                try {thread.Start();}catch {stopping=true;throw;}
            }
        }
        internal void Publish(IDisposable endpoint) {
            if(endpoint==null) throw new ArgumentNullException("endpoint");lock(gate) {
                if(stopping) throw new IOException("Service stopped before its new endpoint was published.");
                if(active!=null) throw new SecurityException("A second service endpoint cannot replace its live owner.");active=endpoint;
            }
        }
        internal void Clear(IDisposable endpoint) {lock(gate) {if(Object.ReferenceEquals(active,endpoint)) active=null;}}
        internal bool Stop() {
            IDisposable endpoint;Thread worker;lock(gate) {stopping=true;endpoint=active;worker=thread;}
            try {if(endpoint!=null) endpoint.Dispose();}catch(Exception) {return false;}
            // Worker-triggered SCM Stop runs OnStop on this very thread. Its
            // effect stack has already unwound; waiting on itself would deadlock.
            try {return worker==null || worker==Thread.CurrentThread || worker.Join(5000);}catch(Exception) {return false;}
        }
        private void Run() {
            bool catastrophic=false;
            try {serve();}catch(Exception error) {catastrophic=error is OutOfMemoryException || error is StackOverflowException || error is AccessViolationException;}
            finally {
                bool unexpected;lock(gate) {unexpected=!stopping;stopping=true;}
                if(catastrophic) terminate("Hosted authority worker could not unwind safely.");
                else if(unexpected) {
                    try {reportFailure(1);}catch(Exception) {terminate("Hosted authority could not report its failed worker as stopped.");}
                }
            }
        }
    }

    internal sealed class HostedAuthorityWindowsService : ServiceBase
    {
        private readonly HostedServiceWorker lifetime;
        internal HostedAuthorityWindowsService() {
            ServiceName=FixedServiceIdentity.Name;CanStop=true;CanShutdown=true;AutoLog=false;
            lifetime=new HostedServiceWorker(Serve,delegate(int code) {ExitCode=code;Stop();},Terminate);
        }
        private void Terminate(string reason) {ExitCode=1;System.Environment.FailFast(reason);}
        private void Running() {if(lifetime.Stopping) throw new IOException("Hosted authority service is stopping; preserve pending state.");FixedServiceIdentity.Require();}
        protected override void OnStart(string[] arguments)
        {
            if(arguments.Length!=0) throw new SecurityException("Service accepts no runtime overrides.");
            lifetime.Start();
        }
        private void Serve()
        {
            // OnStart returns before SCM transitions START_PENDING to RUNNING.
            Stopwatch startup=Stopwatch.StartNew();while(!lifetime.Stopping) {
                try {Running();break;} catch(SecurityException) {if(startup.Elapsed.TotalSeconds>=10) throw;Thread.Sleep(50);}
            }
            while(!lifetime.Stopping) {
                using(NamedPipeServerStream pipe=HostedPipe.Create()) {
                    lifetime.Publish(pipe);
                    try {
                        pipe.WaitForConnection();Running();
                        try {HostedCoordinator.Handle(pipe,Running);} catch(Exception error) {
                            if(error is OutOfMemoryException || error is StackOverflowException || error is AccessViolationException) throw;
                            // No secret, caller bytes, paths or hardware command
                            // bytes are reflected. A refusal is never success.
                            try {if(pipe.IsConnected && !lifetime.Stopping) {
                                    using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-response-v1")) {
                                        writer.Text("refused",32);writer.Blob(Encoding.UTF8.GetBytes("Closed authority operation refused; preserve pending state and use its exact review."),256);
                                        HostedPipe.Write(pipe,writer.Bytes(),Running,TimeSpan.FromSeconds(1));
                                    }
                                }}catch(IOException) {}catch(ObjectDisposedException) {if(!lifetime.Stopping) throw;}
                        }
                    }finally {lifetime.Clear(pipe);}
                }
            }
        }
        protected override void OnStop() {if(!lifetime.Stop()) Terminate("Hosted authority worker or endpoint did not drain within its bounded stop.");}
        protected override void OnShutdown() {OnStop();}
    }

    internal static partial class HostedAuthorityProgram
    {
        private static byte[] OwnerAuthorization()
        {
            Console.Error.Write("Existing TPM owner authorization (hexadecimal; no echo): ");byte[] bytes=new byte[64];int count=0,high=-1;
            try {while(true) {
                ConsoleKeyInfo key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter) break;
                int part=key.KeyChar>='0'&&key.KeyChar<='9'?key.KeyChar-'0':key.KeyChar>='a'&&key.KeyChar<='f'?key.KeyChar-'a'+10:key.KeyChar>='A'&&key.KeyChar<='F'?key.KeyChar-'A'+10:-1;
                if(part<0 || count>=64) throw new SecurityException("Owner authorization must be exact 1..64 hexadecimal bytes.");
                if(high<0) high=part;else {bytes[count++]=(byte)((high<<4)|part);high=-1;}
            }Console.Error.WriteLine();if(count<1 || high>=0) throw new SecurityException("Explicit nonempty owner authorization required.");byte[] result=new byte[count];Buffer.BlockCopy(bytes,0,result,0,count);return result;
            } finally {Array.Clear(bytes,0,bytes.Length);}
        }
        private static int Client(string[] arguments)
        {
            if(Console.IsInputRedirected || Console.IsOutputRedirected) throw new SecurityException("The original interactive client must review and confirm directly.");
            if(arguments.Length>0 && arguments[0]=="infer-enrolled-file") return IngestClient(arguments);
            if(arguments.Length<2) throw new InvalidDataException("Usage: commission DOMAIN ENV RELEASEKEYHEX TIMEKEYHEX HTTPS_TIME_ENDPOINT | commission-resume DOMAIN | commission-abort DOMAIN | status DOMAIN | recover DOMAIN | recover-abort DOMAIN | release-review DESCRIPTION_FILE SIGNATURE_FILE | import DESCRIPTION_FILE SIGNATURE_FILE ARCHIVE_FILE | activate DESCRIPTION_FILE SIGNATURE_FILE | reconcile DESCRIPTION_FILE SIGNATURE_FILE | abandon DESCRIPTION_FILE SIGNATURE_FILE | compute ACTIVE_RELEASE_SHA256 OPERATION PAYLOAD_FILE | compute-recover ACTIVE_RELEASE_SHA256 REQUEST_GENERATION | infer ACTIVE_RELEASE_SHA256 REQUEST_JSON_FILE | infer-recover ACTIVE_RELEASE_SHA256 REQUEST_GENERATION | trust|trust-prepare|trust-finalize|trust-cancel|trust-quarantine DESCRIPTION_FILE OLD_PUBLISHER_SIGNATURE_FILE NEW_PUBLISHER_ACCEPTANCE_FILE");
            string command=arguments[0];bool trustCommand=command=="trust" || command=="trust-prepare" || command=="trust-finalize" || command=="trust-cancel" || command=="trust-quarantine";
            bool readCommand=command=="read-enrolled-file";
            bool computeCommand=command=="compute",computeRecovery=command=="compute-recover";
            bool inferenceCommand=command=="infer",inferenceRecovery=command=="infer-recover";
            bool persistentReadCommand=command=="read-persistent-file",enrollmentCommand=command=="file-enrollment-change",enrollmentStatus=command=="file-enrollment-status";
            bool runtimeCommand=command=="runtime-prepare" || command=="runtime-switch" || command=="runtime-finalize" || command=="runtime-cancel";
            if(command!="commission" && command!="commission-resume" && command!="commission-abort" && command!="status" && command!="recover" && command!="recover-abort" && command!="release-review" && command!="import" && command!="activate" && command!="reconcile" && command!="abandon" && !trustCommand && !runtimeCommand && !readCommand && !persistentReadCommand && !enrollmentCommand && !enrollmentStatus && !computeCommand && !computeRecovery && !inferenceCommand && !inferenceRecovery) throw new InvalidDataException("Client operation is not allowlisted.");
            bool deploymentCommand=command=="release-review" || command=="import" || command=="activate" || command=="reconcile" || command=="abandon";
            if(arguments.Length!=(persistentReadCommand?11:command=="commission" || readCommand?6:command=="import" || command=="runtime-prepare" || trustCommand || computeCommand?4:deploymentCommand || runtimeCommand || computeRecovery || inferenceCommand || inferenceRecovery?3:2)) throw new InvalidDataException("Exact client argument count differs.");
            if(!deploymentCommand && !trustCommand && !runtimeCommand && !readCommand && !persistentReadCommand && !enrollmentCommand && !enrollmentStatus && !computeCommand && !computeRecovery && !inferenceCommand && !inferenceRecovery) PlatformCustodyProtocol.Index(arguments[1]);
            if(computeRecovery || inferenceRecovery) {Wire.Bytes(arguments[1],32,true);Wire.Bytes(arguments[2],32,true);}
            HostedEnrollmentInputs enrollment=enrollmentCommand?new HostedEnrollmentInputs(arguments[1]):null;
            if(enrollmentStatus) Wire.Bytes(arguments[1],32,true);
            using(HostedPersistentReadInputs persistent=persistentReadCommand?new HostedPersistentReadInputs(arguments):null)
            using(HostedReadInputs read=readCommand?new HostedReadInputs(arguments,true):null)
            using(HostedComputeInputs compute=computeCommand?new HostedComputeInputs(arguments):null)
            using(HostedInferenceInputs inference=inferenceCommand?new HostedInferenceInputs(arguments):null)
            using(HostedRuntimeInputs runtime=runtimeCommand?new HostedRuntimeInputs(arguments,command=="runtime-prepare"):null)
            using(HostedClientInputs inputs=new HostedClientInputs(command,arguments))
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",HostedPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)) {
                pipe.Connect(3000);Stopwatch clientAge=Stopwatch.StartNew();TimeSpan clientPurpose=TimeSpan.FromSeconds(command=="import" || command=="activate" || command=="reconcile" || command=="runtime-prepare"?1800:inferenceCommand?HostedInferenceContract.PurposeSeconds:30);
                Action check=delegate {HostedPipe.CheckServer(pipe);if(read!=null) read.Check();if(persistent!=null) persistent.Read.Check();if(compute!=null) compute.Check();if(inference!=null) inference.Check();if(clientAge.Elapsed>=clientPurpose) throw new SecurityException("Exact original client purpose deadline expired; partial transfer is possible and no complete read/publication is inferred.");};check();
                using(Wire.Writer hello=new Wire.Writer("luma-windows-hosted-hello-v1")) {hello.U32(1);HostedPipe.Write(pipe,hello.Bytes(),check,TimeSpan.FromSeconds(30));}
                using(Wire.Writer request=new Wire.Writer("luma-windows-hosted-request-v1")) {
                    request.Text(command,32);
                    if(inferenceCommand) {request.Fixed(Wire.Bytes(inference.Release,32,true),32);request.Blob(inference.Request.Bytes,GuestInferenceRequest.MaximumEncoded);}
                    else if(computeCommand) {request.Fixed(Wire.Bytes(compute.Release,32,true),32);request.Blob(compute.Request.Bytes,HostedComputeContract.MaximumRequestBytes);}
                    else if(computeRecovery || inferenceRecovery) {request.Fixed(Wire.Bytes(arguments[1],32,true),32);request.Fixed(Wire.Bytes(arguments[2],32,true),32);}
                    else if(enrollmentCommand) request.Blob(enrollment.Intent.Encode(),2048);
                    else if(enrollmentStatus) request.Fixed(Wire.Bytes(arguments[1],32,true),32);
                    else if(persistentReadCommand) {request.Blob(persistent.Selection.Encode(),512);request.Blob(persistent.Read.Intent.Encode(),2048);}
                    else if(readCommand) request.Blob(read.Intent.Encode(),2048);
                    else if(runtimeCommand) {request.Blob(runtime.Description,2048);request.Fixed(runtime.Signature,64);}
                    else if(trustCommand) {request.Blob(inputs.Description,3072);request.Fixed(inputs.Signature,64);request.Fixed(inputs.Acceptance,64);}
                    else if(deploymentCommand) {
                        request.Blob(inputs.Description,60000);request.Fixed(inputs.Signature,64);
                    } else {
                        request.Text(arguments[1],32);if(command=="commission") {request.Text(arguments[2],10);request.Fixed(Wire.Bytes(arguments[3],72,true),72);request.Fixed(Wire.Bytes(arguments[4],72,true),72);request.Text(HostedTimeEndpoint.Validate(arguments[5]),2048);}
                    }
                    HostedPipe.Write(pipe,request.Bytes(),check,TimeSpan.FromSeconds(30));
                }
                while(true) {
                    byte[] response=HostedPipe.Read(pipe,check,clientPurpose);
                    try {using(Wire.Reader reader=new Wire.Reader(response,"luma-windows-hosted-response-v1")) {
                        string kind=reader.Text(32);byte[] payload=reader.Blob(60000);reader.End();
                        try {
                        if(kind=="refused") throw new SecurityException(new UTF8Encoding(false,true).GetString(payload));
                        if(kind=="utc-challenge") {if(!deploymentCommand && !trustCommand && !runtimeCommand && !readCommand && !persistentReadCommand && !enrollmentCommand && !computeCommand && !computeRecovery && !inferenceCommand && !inferenceRecovery) throw new SecurityException("UTC relay cannot cross into another client purpose.");HostedTimeEndpoint.Deliver(pipe,payload,inferenceCommand?inference.Release:computeCommand?compute.Release:computeRecovery || inferenceRecovery?arguments[1]:Wire.Hash(enrollmentCommand?enrollment.Intent.Encode():persistentReadCommand?persistent.Read.Intent.Encode():readCommand?read.Intent.Encode():runtimeCommand?runtime.Description:inputs.Description),check);continue;}
                        if(kind=="inference-chunk") {if(!inferenceCommand) throw new SecurityException("Model output crossed into another original-client purpose.");byte[] ack=inference.Receiver.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                        if(kind=="inference-completed") {if(!inferenceCommand) throw new SecurityException("Inference receipt crossed into another original-client purpose.");inference.Receiver.Finish(payload);inference.Print(check);return 0;}
                        if(kind=="inference-recovered") {
                            if(!inferenceRecovery) throw new SecurityException("Inference recovery crossed into another original-client purpose.");
                            using(Wire.Reader receipt=new Wire.Reader(payload,"luma-windows-hosted-inference-recovered-v1")) {
                                if(Wire.Hex(receipt.Fixed(32))!=arguments[1] || Wire.Hex(receipt.Fixed(32))!=arguments[2]) throw new SecurityException("Inference recovery substituted exact selected release or generation.");
                                string head=Wire.Hex(receipt.Fixed(32));Wire.Bytes(head,32,true);if(receipt.U8()!=0 || receipt.U8()!=0) throw new SecurityException("Inference recovery claims result success or qualification.");receipt.End();Console.WriteLine("Closed exact inference generation after original exit and confined drainage; head "+head+". No model rerun or partial output adoption.");return 0;
                            }
                        }
                        if(kind=="compute-chunk") {if(!computeCommand) throw new SecurityException("Inert compute bytes crossed into another original-client purpose.");byte[] ack=compute.Receiver.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                        if(kind=="compute-completed") {if(!computeCommand) throw new SecurityException("Compute receipt crossed into another original-client purpose.");compute.Receiver.Finish(payload);compute.Print(check);return 0;}
                        if(kind=="compute-recovered") {
                            if(!computeRecovery) throw new SecurityException("Compute recovery crossed into another original-client purpose.");
                            using(Wire.Reader receipt=new Wire.Reader(payload,"luma-windows-hosted-compute-recovered-v1")) {
                                if(Wire.Hex(receipt.Fixed(32))!=arguments[1] || Wire.Hex(receipt.Fixed(32))!=arguments[2]) throw new SecurityException("Compute recovery substituted selected exact release or request generation.");
                                string head=Wire.Hex(receipt.Fixed(32));Wire.Bytes(head,32,true);if(receipt.U8()!=0 || receipt.U8()!=0) throw new SecurityException("Compute recovery claims unobserved result success or production qualification.");receipt.End();
                                Console.WriteLine("Closed exact inert compute generation after original-controller exit and confined guest drain; journal head "+head+". No request replay, result recovery/publication or production qualification.");return 0;
                            }
                        }
                        if(kind=="persistent-read-chunk") {if(!persistentReadCommand) throw new SecurityException("Persistent-source bytes crossed into another original-client purpose.");byte[] ack=persistent.Read.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                        if(kind=="persistent-read-completed") {if(!persistentReadCommand) throw new SecurityException("Persistent read receipt crossed into another original-client purpose.");persistent.Complete(payload);Console.WriteLine(persistent.Summary());return 0;}
                        if(kind=="read-chunk") {if(!readCommand) throw new SecurityException("Source bytes crossed into another original-client purpose.");byte[] ack=read.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                        if(kind=="read-completed") {if(!readCommand) throw new SecurityException("Read receipt crossed into another original-client purpose.");read.Completed(payload);Console.WriteLine(read.Summary());return 0;}
                        if(kind=="runtime-next") {if(command!="runtime-prepare") throw new SecurityException("Runtime transfer crossed its separate original-client preparation purpose.");HostedPipe.Write(pipe,runtime.Part(payload),check,TimeSpan.FromSeconds(30));continue;}
                        if(kind=="package-next") {if(command!="import") throw new SecurityException("Archive transfer crossed its separately reviewed import purpose.");HostedPipe.Write(pipe,inputs.PackagePart(payload),check,TimeSpan.FromSeconds(30));continue;}
                        if(kind=="review") {
                            string hash=Wire.Hash(payload);using(Wire.Reader review=new Wire.Reader(payload,"luma-windows-hosted-reviewed-action-v1")) {
                                string action=review.Text(32);review.Fixed(32);byte[] exact=review.Blob(8192);string detail=review.Text(16000);review.End();
                                if(action!=command) throw new SecurityException("Service review substituted the requested command.");if(inferenceCommand) inference.Reviewed(exact,hash);
                                else if(inferenceRecovery) {using(Wire.Reader recovery=new Wire.Reader(exact,"luma-windows-hosted-inference-recovery-v1")) {DeploymentEvent pending=DeploymentEvent.Decode(recovery.Blob(4096));if(pending.Purpose!=4 || pending.ReleaseSha256!=arguments[1] || pending.Generation!=arguments[2] || pending.Controller!=0 || pending.ObservationKind!=0) throw new SecurityException("Inference recovery review substituted exact outstanding generation.");Wire.Bytes(Wire.Hex(recovery.Fixed(32)),32,true);recovery.End();}}
                                else if(computeCommand) compute.Reviewed(exact,hash);
                                else if(computeRecovery) {using(Wire.Reader recovery=new Wire.Reader(exact,"luma-windows-hosted-compute-recovery-v1")) {DeploymentEvent pending=DeploymentEvent.Decode(recovery.Blob(4096));if(pending.Purpose!=3 || pending.ReleaseSha256!=arguments[1] || pending.Generation!=arguments[2] || pending.Controller!=0 || pending.ObservationKind!=0) throw new SecurityException("Compute recovery review substituted the selected exact outstanding request generation.");Wire.Bytes(Wire.Hex(recovery.Fixed(32)),32,true);recovery.End();}}
                                else if(enrollmentCommand) enrollment.Reviewed(exact);else if(persistentReadCommand) persistent.Reviewed(exact,hash);else if(readCommand) read.Reviewed(exact,hash);else if(runtimeCommand) runtime.Reviewed(exact);else if(deploymentCommand || trustCommand) inputs.Reviewed(command,exact);
                                else if(command=="commission" || command=="commission-resume") {
                                    CommissionIntent proposed=CommissionIntent.Decode(exact);if(proposed.Domain!=arguments[1]) throw new SecurityException("Commissioning review changed its selected domain.");
                                    if(command=="commission" && (proposed.Environment!=arguments[2] || !Wire.Equal(proposed.ReleaseKey,Wire.Bytes(arguments[3],72,true)) || !Wire.Equal(proposed.TimeKey,Wire.Bytes(arguments[4],72,true)) || proposed.TimeEndpoint!=HostedTimeEndpoint.Validate(arguments[5]))) throw new SecurityException("Commissioning review substituted the exact original-client environment/key pins/UTC endpoint.");
                                }
                                Console.WriteLine(detail);
                            }
                            Console.WriteLine("Confirm this exact action by entering: CONFIRM "+hash);
                            if(Console.ReadLine()!="CONFIRM "+hash) throw new SecurityException("Exact Admin review was not confirmed.");
                            using(Wire.Writer confirmation=new Wire.Writer("luma-windows-hosted-confirm-v1")) {confirmation.Fixed(Wire.Bytes(hash,32,true),32);HostedPipe.Write(pipe,confirmation.Bytes(),check,TimeSpan.FromSeconds(30));}
                            if(command=="commission" || command=="commission-resume") {
                                byte[] auth=OwnerAuthorization(),frame=null;
                                try {using(Wire.Writer secret=new Wire.Writer("luma-windows-hosted-owner-authorization-v1")) {secret.Blob(auth,64);frame=secret.Bytes();HostedPipe.Write(pipe,frame,check,TimeSpan.FromSeconds(30));}}
                                finally {Array.Clear(auth,0,auth.Length);if(frame!=null) Array.Clear(frame,0,frame.Length);}
                            }
                            continue;
                        }
                        if(kind=="commissioned") {
                            if(command!="commission" && command!="commission-resume" && command!="commission-abort") throw new SecurityException("Commissioning result crossed its original client purpose.");
                            AuthorityIdentity identity=AuthorityIdentity.Decode(payload);Console.WriteLine("Commissioned exact "+identity.Domain+" identity "+Wire.Hash(payload)+"; no guest activated; production qualification false.");return 0;
                        }
                        if(kind=="file-enrollment-changed") {
                            if(!enrollmentCommand) throw new SecurityException("Persistent enrollment completion crossed its original-client command.");
                            using(Wire.Reader changed=new Wire.Reader(payload,"luma-windows-hosted-file-enrollment-result-v1")) {if(Wire.Hex(changed.Fixed(32))!=Wire.Hash(enrollment.Intent.Encode())) throw new SecurityException("File enrollment receipt substituted original exact policy.");string entry=Wire.Hex(changed.Fixed(32)),registry=Wire.Hex(changed.Fixed(32)),head=Wire.Hex(changed.Fixed(32));Wire.Bytes(entry,32,true);Wire.Bytes(head,32,true);
                                if(registry!=entry || changed.U8()!=(enrollment.Intent.Action==FileEnrollmentAction.Revoke?1:0) || changed.U8()!=0) throw new SecurityException("File enrollment result changed registry/revocation or claimed qualification.");changed.End();Console.WriteLine("Protected exact-file policy "+enrollment.Intent.Action+" committed: ID "+enrollment.Intent.Enrollment+" generation "+enrollment.Intent.Generation+"; entry/registry "+entry+"; actual journal head "+head+". Every actual read still needs fresh30-second original-session authorization. No source write, Linux grant or qualification.");return 0;}
                        }
                        if(kind=="file-enrollment-status") {
                            if(!enrollmentStatus) throw new SecurityException("File enrollment metadata crossed its selected inspection purpose.");
                            using(Wire.Reader status=new Wire.Reader(payload,"luma-windows-hosted-file-enrollment-status-v2")) {if(Wire.Hex(status.Fixed(32))!=arguments[1]) throw new SecurityException("File enrollment inspection changed its selected ID.");string registry=Wire.Hex(status.Fixed(32)),head=Wire.Hex(status.Fixed(32));Wire.Bytes(registry,32,true);Wire.Bytes(head,32,true);uint identities=status.U32(),active=status.U32(),controls=status.U32();
                                if(identities>64 || active>identities || controls>256 || status.U32()!=64 || status.U32()!=256 || status.U32()!=64 || status.U32()!=1048576 || status.U64()!=FileEnrollmentIntent.MaximumLifetimeMilliseconds || status.U32()!=30) throw new SecurityException("File enrollment inspection changed its closed finite caps.");uint credits=status.U32();if(credits>active || status.U32()!=HostedJournalCapacity.ReservedEventBytes || status.U8()!=1 || status.U8()!=0 || status.U8()!=0 || status.U8()!=0) throw new SecurityException("File policy capacity metadata claimed another bound, physical/namespace reservation or unlimited recovery.");byte exists=status.U8();if(exists>1) throw new SecurityException("File enrollment existence flag differs.");
                                Console.WriteLine("Registry source: "+registry+"\nCurrent journal head: "+head+"\nLifetime IDs: "+identities+"/64; active policies: "+active+"; controls: "+controls+"/256. Max64 generations (64 revoke only),1MiB exact bytes,30-day TTL, fresh30-second reads.\nLogical signed-journal tail: "+active+" healthy revocations + "+credits+" finite uncertain-write recovery spares,8192 bytes each. Zero-spare terminal revocation may succeed, but a further uncertain write remains globally fenced when a reviewed abort cannot fit. Physical free space, private namespace capacity and unlimited faults are NOT reserved or qualified; full journal continuation remains open.");
                                if(exists==1) {FileEnrollmentIntent policy=FileEnrollmentIntent.Decode(status.Blob(2048));string entry=Wire.Hex(status.Fixed(32)),snapshot=Wire.Hex(status.Fixed(32));Wire.Bytes(entry,32,true);Wire.Bytes(snapshot,32,true);ulong start=status.U64(),end=status.U64();byte revoked=status.U8();if(policy.Enrollment!=arguments[1] || revoked>1 || (revoked==1)!=(policy.Action==FileEnrollmentAction.Revoke) || start==0 || end<=start || end-start>FileEnrollmentIntent.MaximumLifetimeMilliseconds) throw new SecurityException("File enrollment inspection changed policy identity, revocation or finite interval.");Console.WriteLine("Generation: "+policy.Generation+"\nEntry SHA256: "+entry+"\nRevoked: "+(revoked==1)+"\nObject fingerprint: "+snapshot+"\nOwner/source: "+policy.Read.Owner+" / "+policy.Read.Path+"\nRead bytes/SHA256: "+policy.Read.Bytes+" / "+policy.Read.Sha256+"\nUTC half-open interval: ["+start+", "+end+")");}
                                byte uncertain=status.U8();if(uncertain>1 || status.U8()!=0 || status.U8()!=0) throw new SecurityException("Metadata inspection claims read admission or qualification.");status.End();Console.WriteLine("Uncertain write fence: "+(uncertain==1)+". Metadata only; no source accessed, fresh file-read session admitted or production qualification.");return 0;}
                        }
                        if(kind=="status") {
                            if(command!="status" && command!="recover") throw new SecurityException("Status result crossed its original client purpose.");
                            using(Wire.Reader status=new Wire.Reader(payload,"luma-windows-hosted-status-v4")) {
                                AuthorityIdentity identity=AuthorityIdentity.Decode(status.Blob(4096));ulong sequence=status.U64();string head=Wire.Hex(status.Fixed(32));byte phase=status.U8();
                                byte active=status.U8();if(phase>3 || active>1 || status.U8()!=0 || status.U8()!=0) throw new SecurityException("Status claims unsupported qualification or Linux authority.");
                                string pending=status.Text(64);byte purpose=status.U8();uint controller=status.U32();ulong creation=status.U64();
                                ulong trustGeneration=status.U64();string trustSource=Wire.Hex(status.Fixed(32));byte[] publisher=AuthorityIdentity.Public(status.Fixed(72)),time=AuthorityIdentity.Public(status.Fixed(72));string endpoint=HostedTimeEndpoint.Validate(status.Text(2048));byte revokedPublisher=status.U8(),revokedTime=status.U8();string preparedTrust=status.Text(64);
                                ulong runtimeGeneration=status.U64();string runtimeSource=Wire.Hex(status.Fixed(32)),bundle=Wire.Hex(status.Fixed(32)),wsl=Wire.Hex(status.Fixed(32)),slot=status.Text(64),pendingRuntime=status.Text(64),pendingSlot=status.Text(64);status.End();
                                if(trustGeneration>1024 || revokedPublisher>1 || revokedTime>1) throw new SecurityException("Trust status generation or revocation flags differ.");Wire.Bytes(trustSource,32,true);
                                if(preparedTrust.Length!=0) Wire.Bytes(preparedTrust,32,true);
                                if(runtimeGeneration>1024 || (pendingRuntime.Length==0)!=(pendingSlot.Length==0)) throw new SecurityException("Runtime status generation/pending shape differs.");Wire.Bytes(runtimeSource,32,true);Wire.Bytes(bundle,32,true);Wire.Bytes(wsl,32,true);if(slot.Length!=0) Wire.Bytes(slot,32,true);if(pendingRuntime.Length!=0) {Wire.Bytes(pendingRuntime,32,true);Wire.Bytes(pendingSlot,32,true);}
                                HostedStatusShape.Require(purpose,pending,controller,creation);
                                Console.WriteLine(identity.Domain+" journal sequence "+sequence+"; phase "+((RecoveryPhase)phase)+"; actual TPM head "+head+
                                    "; compute-only slot active="+(active==1)+"; outstanding generation="+(pending.Length==0?"none":pending)+"; production qualification false.");
                                Console.WriteLine("Trust generation "+trustGeneration+"; source "+trustSource+"; publisher revoked="+(revokedPublisher==1)+"; UTC revoked="+(revokedTime==1)+"; prepared UTC source="+(preparedTrust.Length==0?"none":preparedTrust)+"\nPublisher public blob: "+Wire.Hex(publisher)+"\nUTC public blob: "+Wire.Hex(time)+"\nUTC endpoint: "+endpoint);
                                Console.WriteLine("Runtime generation "+runtimeGeneration+"; source "+runtimeSource+"; bundle "+bundle+"; WSL "+wsl+"; slot "+(slot.Length==0?"initial":slot)+"; pending runtime="+(pendingRuntime.Length==0?"none":pendingRuntime)+"; pending slot="+(pendingSlot.Length==0?"none":pendingSlot));return 0;
                            }
                        }
                        if(kind=="release-reviewed") {
                            if(command!="release-review") throw new SecurityException("Release review crossed its original client purpose.");
                            using(Wire.Reader reviewed=new Wire.Reader(payload,"luma-windows-hosted-reviewed-release-v1")) {
                                string digest=Wire.Hex(reviewed.Fixed(32));ulong sequence=reviewed.U64();
                                if(reviewed.U8()!=0 || reviewed.U8()!=0 || reviewed.U8()!=0) throw new SecurityException("Release review claims installation, execution authority or qualification.");reviewed.End();
                                Console.WriteLine("Publisher signature and fresh independent UTC verified for release "+sequence+", descriptor "+digest+". No image imported, no guest activated, production qualification false.");return 0;
                            }
                        }
                        if(kind=="nv-aborted") {
                            if(command!="recover-abort") throw new SecurityException("NV abort result crossed its original client purpose.");
                            using(Wire.Reader aborted=new Wire.Reader(payload,"luma-windows-hosted-nv-aborted-v1")) {
                                string domain=aborted.Text(32);ulong sequence=aborted.U64();string head=Wire.Hex(aborted.Fixed(32));if(domain!=arguments[1] || sequence<2 || aborted.U8()!=0) throw new SecurityException("NV abort source or completion claim differs.");aborted.End();Wire.Bytes(head,32,true);
                                Console.WriteLine("Exact pending NV write aborted at sequence "+sequence+"; signed previous intent retained. No guest completion or resource release is implied.");return 0;
                            }
                        }
                        if(kind=="trust-changed") {
                            if(command!="trust" && command!="trust-finalize") throw new SecurityException("Trust result crossed its original client purpose.");
                            using(Wire.Reader changed=new Wire.Reader(payload,"luma-windows-hosted-trust-result-v1")) {
                                if(Wire.Hex(changed.Fixed(32))!=Wire.Hash(inputs.Description) || changed.U64()!=inputs.Trust.Generation) throw new SecurityException("Trust result substituted the exact reviewed transition.");Wire.Bytes(Wire.Hex(changed.Fixed(32)),32,true);
                                if(changed.U8()!=0) throw new SecurityException("Trust result claims unsupported qualification.");changed.End();Console.WriteLine("Exact reviewed trust generation "+inputs.Trust.Generation+" committed to original TPM/NV authority. No guest effect or production qualification.");return 0;
                            }
                        }
                        if(kind=="trust-prepared") {
                            if(command!="trust-prepare") throw new SecurityException("Prepared trust result crossed its original client purpose.");
                            using(Wire.Reader prepared=new Wire.Reader(payload,"luma-windows-hosted-trust-prepared-result-v1")) {
                                if(Wire.Hex(prepared.Fixed(32))!=Wire.Hash(inputs.Description)) throw new SecurityException("Prepared trust result substituted the original source.");Wire.Bytes(Wire.Hex(prepared.Fixed(32)),32,true);if(prepared.U8()!=0) throw new SecurityException("Prepared trust result claims qualification.");prepared.End();
                                Console.WriteLine("Exact UTC handoff prepared in actual TPM/NV journal. Keys are unchanged; new effects are fenced. Commission the independently reviewed native UTC replacement, then run trust-finalize with the same descriptor/proofs.");return 0;
                            }
                        }
                        if(kind=="runtime-observed") {
                            if(!runtimeCommand) throw new SecurityException("Runtime result crossed its original client purpose.");
                            using(Wire.Reader observed=new Wire.Reader(payload,"luma-windows-hosted-runtime-result-v1")) {
                                if(Wire.Hex(observed.Fixed(32))!=Wire.Hash(runtime.Description)) throw new SecurityException("Runtime result substituted the exact source.");Wire.Bytes(Wire.Hex(observed.Fixed(32)),32,true);byte mode=observed.U8();ulong generation=observed.U64();Wire.Bytes(Wire.Hex(observed.Fixed(32)),32,true);
                                if(mode!=(command=="runtime-cancel"?2:command=="runtime-finalize"?1:0) || generation!=(mode==0?runtime.Update.Generation-1:runtime.Update.Generation) || observed.U8()!=0) throw new SecurityException("Runtime result mode/generation/qualification differs.");observed.End();
                                Console.WriteLine(mode==0?"Exact new bundle staged and SCM configured; previous files retained. Explicitly stop/start LumaHostedAuthority, then run runtime-finalize. No activation or qualification claimed.":mode==1?"Actual post-restart full bundle/WSL pins and SCM image finalized in the original TPM/NV journal; no production qualification.":"Prepared runtime cancelled; SCM points to the retained previous image. Restart explicitly if necessary; partial/new files are quarantined, never overwritten or deleted.");return 0;
                            }
                        }
                        if(kind=="trust-cancelled") {
                            if(command!="trust-cancel" && command!="trust-quarantine") throw new SecurityException("Trust cancellation result crossed its original client purpose.");
                            using(Wire.Reader cancelled=new Wire.Reader(payload,"luma-windows-hosted-trust-cancelled-result-v1")) {
                                if(Wire.Hex(cancelled.Fixed(32))!=Wire.Hash(inputs.Description) || cancelled.U64()!=inputs.Trust.Generation) throw new SecurityException("Trust cancellation substituted its original source/generation.");Wire.Bytes(Wire.Hex(cancelled.Fixed(32)),32,true);
                                if(cancelled.U8()!=(command=="trust-quarantine"?1:0) || cancelled.U8()!=0) throw new SecurityException("Trust cancellation substituted its mode or qualification.");cancelled.End();
                                Console.WriteLine(command=="trust-quarantine"?"Prepared handoff closed without activation; old UTC is revoked. A fresh exact recover-UTC trust transition is required before effects.":"Prepared handoff cancelled with fresh current-key UTC; key pins unchanged. Old descriptor generation cannot be replayed.");return 0;
                            }
                        }
                        if(kind=="deployment-observed") {
                            if(command!="import" && command!="activate") throw new SecurityException("Deployment result crossed its client purpose.");
                            using(Wire.Reader observed=new Wire.Reader(payload,"luma-windows-hosted-deployment-result-v1")) {
                                byte purpose=observed.U8();string digest=Wire.Hex(observed.Fixed(32));ulong sequence=observed.U64();Wire.Bytes(Wire.Hex(observed.Fixed(32)),32,true);
                                if(purpose!=(command=="import"?1:2) || digest!=Wire.Hash(inputs.Description) || sequence!=inputs.Release.Sequence || observed.U8()!=0 || observed.U8()!=0)
                                    throw new SecurityException("Actual deployment result substituted source/purpose or claims Linux/production authority.");observed.End();
                                Console.WriteLine(command+" observed for exact release "+sequence+" ("+digest+"). Compute-only hosted profile; no Linux product authority or production qualification.");return 0;
                            }
                        }
                        if(kind=="deployment-reconciled") {
                            if(command!="reconcile" && command!="abandon") throw new SecurityException("Recovery result crossed its actual client purpose.");
                            using(Wire.Reader observed=new Wire.Reader(payload,"luma-windows-hosted-deployment-reconciled-v1")) {
                                byte abandoned=observed.U8();string digest=Wire.Hex(observed.Fixed(32));ulong sequence=observed.U64();Wire.Bytes(Wire.Hex(observed.Fixed(32)),32,true);
                                if(abandoned!=(command=="abandon"?1:0) || digest!=Wire.Hash(inputs.Description) || sequence!=inputs.Release.Sequence || observed.U8()!=0 || observed.U8()!=0)
                                    throw new SecurityException("Reconciliation changed source/purpose or claimed Linux/production authority.");observed.End();
                                Console.WriteLine(command+" recorded for exact release "+sequence+". Previous active slot preserved on abandonment; private artifacts are quarantined, not deleted. Production qualification false.");return 0;
                            }
                        }
                        throw new InvalidDataException("Unexpected closed service response.");
                        }finally {Array.Clear(payload,0,payload.Length);}
                    }}finally {Array.Clear(response,0,response.Length);}
                }
            }
        }
        public static int Main(string[] arguments)
        {
            try {
                if(arguments.Length>0 && arguments[0]=="read-intent") return HostedReadInputs.Describe(arguments);
                if(arguments.Length>0 && arguments[0]=="enrollment-intent") return HostedEnrollmentInputs.Describe(arguments);
                if(arguments.Length==1 && arguments[0]=="service") {if(System.Environment.UserInteractive) throw new SecurityException("Service entrypoint requires actual SCM launch.");using(HostedAuthorityWindowsService service=new HostedAuthorityWindowsService()) {ServiceBase.Run(service);return service.ExitCode;}}
                return Client(arguments);
            } catch(Exception error) {
                if(error is OutOfMemoryException || error is StackOverflowException || error is AccessViolationException) throw;
                Console.Error.WriteLine("Hosted authority refused: "+error.Message);return 1;
            }
        }
    }
}
