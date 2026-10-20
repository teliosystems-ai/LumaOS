using System;
using System.Collections.Generic;
using System.IO;
using System.Security;

namespace Luma.Windows.Hosted
{
    public sealed class DeploymentEvent
    {
        public byte Purpose {get;private set;}
        public string ReleaseSha256 {get;private set;}
        public ulong ReleaseSequence {get;private set;}
        public string Generation {get;private set;}
        public ulong HostBootCreation {get;private set;}
        public string PackageLeaf {get;private set;}
        public uint Controller {get;private set;}
        public ulong ControllerCreation {get;private set;}
        public string ObservationSha256 {get;private set;}
        public byte ObservationKind {get;private set;}
        public DeploymentEvent(byte purpose,string release,ulong sequence,string generation,ulong boot,string package,uint controller,ulong creation,byte observationKind,string observation)
        {
            if((purpose<1 || purpose>5) || sequence<1 || sequence>9007199254740991UL || boot<1 || (controller==0)!=(creation==0) || (controller!=0 && controller<4))
                throw new InvalidDataException("Typed deployment purpose, sequence or actual controller binding differs.");
            Wire.Bytes(release,32,true);Wire.Bytes(generation,32,true);Wire.Bytes(observation,32,false);
            bool zero=observation==new string('0',64);
            if(observationKind>2 || (observationKind!=0 && zero) || (observationKind==0 && controller==0 && !zero)) throw new SecurityException("Typed controller outcome or observation commitment differs.");
            if(package==null || !System.Text.RegularExpressions.Regex.IsMatch(package,@"\Aticket-package-[0-9a-f]{32}\.tar\z")) throw new InvalidDataException("Deployment package is not a closed private artifact leaf.");
            Purpose=purpose;ReleaseSha256=release;ReleaseSequence=sequence;Generation=generation;HostBootCreation=boot;PackageLeaf=package;Controller=controller;ControllerCreation=creation;ObservationKind=observationKind;ObservationSha256=observation;
        }
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-deployment-event-v1")) {
                writer.U8(Purpose);writer.Fixed(Wire.Bytes(ReleaseSha256,32,true),32);writer.U64(ReleaseSequence);writer.Fixed(Wire.Bytes(Generation,32,true),32);writer.U64(HostBootCreation);
                writer.Text(PackageLeaf,80);writer.U32(Controller);writer.U64(ControllerCreation);writer.U8(ObservationKind);writer.Fixed(Wire.Bytes(ObservationSha256,32,false),32);return writer.Bytes();
            }
        }
        public static DeploymentEvent Decode(byte[] bytes)
        {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-deployment-event-v1")) {
                DeploymentEvent result=new DeploymentEvent(reader.U8(),Wire.Hex(reader.Fixed(32)),reader.U64(),Wire.Hex(reader.Fixed(32)),reader.U64(),reader.Text(80),reader.U32(),reader.U64(),reader.U8(),Wire.Hex(reader.Fixed(32)));
                reader.End();if(!Wire.Equal(bytes,result.Encode())) throw new SecurityException("Noncanonical typed deployment event.");return result;
            }
        }
        internal bool SameAdmission(DeploymentEvent other)
        {return other!=null && Purpose==other.Purpose && ReleaseSha256==other.ReleaseSha256 && ReleaseSequence==other.ReleaseSequence && Generation==other.Generation && HostBootCreation==other.HostBootCreation && PackageLeaf==other.PackageLeaf;}
        internal DeploymentEvent WithController(uint process,ulong creation,byte outcome,string observation)
        {return new DeploymentEvent(Purpose,ReleaseSha256,ReleaseSequence,Generation,HostBootCreation,PackageLeaf,process,creation,outcome,observation);}
    }

    // A rebuildable state machine, not a second mutable head/index. Every
    // transition is a genuine signed record already joined to actual NV.
    public sealed class DeploymentHistory
    {
        public DeploymentEvent Pending {get;private set;}
        public DeploymentEvent Worker {get;private set;}
        public DeploymentEvent Active {get;private set;}
        public int CompletedControllers {get;private set;}
        public int SuccessfulControllers {get;private set;}
        public DeploymentEvent LastSuccess {get;private set;}
        public string LastControllerRequestSha256 {get;private set;}
        private readonly Dictionary<string,DeploymentEvent> imported=new Dictionary<string,DeploymentEvent>(StringComparer.Ordinal);
        private readonly HashSet<string> generations=new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string,HostedWorkspaceAccountState> workspaces=new Dictionary<string,HostedWorkspaceAccountState>(StringComparer.Ordinal);
        public HostedWorkspacePreparation PendingWorkspace {get;private set;}
        public HostedWorkspaceAccountState Workspace(string release) {HostedWorkspaceAccountState result;return workspaces.TryGetValue(release,out result)?result:null;}
        private DeploymentHistory() {}
        public DeploymentEvent Imported(string release) {DeploymentEvent result;return imported.TryGetValue(release,out result)?result:null;}
        public void RequireFreshGeneration(string generation)
        {Wire.Bytes(generation,32,true);if(Pending!=null || generations.Contains(generation)) throw new SecurityException("A resource generation is already outstanding or was previously used; no new journal write or execution is admitted.");}
        public string DrainRequestSha256()
        {
            if(Pending==null) throw new SecurityException("Drain requires the exact outstanding resource generation.");
            // Import's sole controller is wsl --import, not a guest compute
            // request. Before any controller, no request was ever dispatched.
            if(Pending.Purpose==1 || (Worker==null && CompletedControllers==0)) return Pending.Generation;
            string request=Worker==null?LastControllerRequestSha256:Worker.ObservationSha256;
            if(request==null || request==new string('0',64)) throw new SecurityException("Legacy controller has no durably bound exact request; preserve its fence for separately reviewed legacy cleanup, never guess or rerun.");
            Wire.Bytes(request,32,true);return request;
        }
        public static void ValidateNext(AuthorityIdentity identity,JournalHistory history,JournalEntry candidate,Action check,CommissionIntent workspaceIntent=null)
        {
            if(identity==null || history==null || candidate==null || check==null) throw new ArgumentNullException("candidate");
            // Validate the actual signed prospective transition before staging
            // even its dispatch ticket. Accepted NV history must never be used
            // as a speculative parser for an invalid or reused generation.
            List<byte[]> records=new List<byte[]>();foreach(JournalEntry entry in history.Entries) {check();records.Add(entry.Bytes);}records.Add(candidate.Bytes);
            JournalHistory prospective=JournalHistory.Replay(identity,records.ToArray(),check);
            Replay(prospective,check);
            if(candidate.Kind==JournalKind.WorkspacePrepared) {
                if(workspaceIntent==null) throw new SecurityException("Prospective workspace transition requires the actual protected commissioned trust context.");
                workspaceIntent.ValidateGenesis(identity,prospective.Entries[0].Payload);HostedTrustState.Replay(identity,workspaceIntent,prospective,check);
            }
            check();
        }
        public static DeploymentHistory Replay(JournalHistory history)
        {return Replay(history,delegate {});}
        public static DeploymentHistory Replay(JournalHistory history,Action check)
        {
            if(check==null) throw new ArgumentNullException("check");check();
            if(history==null || history.Entries.Length==0 || history.Entries[0].Kind!=JournalKind.Commission) throw new SecurityException("Deployment history lacks commissioned genesis.");
            DeploymentHistory state=new DeploymentHistory();JournalEntry[] records=history.Entries;
            for(int index=1;index<records.Length;index++) {
                check();
                if(state.Pending!=null && state.Pending.Purpose>=3 && (records[index].Kind==JournalKind.TrustChanged || records[index].Kind==JournalKind.TrustPrepared || records[index].Kind==JournalKind.TrustCancelled ||
                    records[index].Kind==JournalKind.RuntimePrepared || records[index].Kind==JournalKind.RuntimeActivated || records[index].Kind==JournalKind.RuntimeCancelled ||
                    records[index].Kind==JournalKind.FileEnrolled || records[index].Kind==JournalKind.FileEnrollmentRevoked))
                    throw new SecurityException("Unresolved compute or inference generation cannot be crossed by new trust, runtime or file-policy effects.");
                if(records[index].Kind==JournalKind.NvWriteAborted || records[index].Kind==JournalKind.TrustChanged || records[index].Kind==JournalKind.TrustPrepared || records[index].Kind==JournalKind.TrustCancelled ||
                    records[index].Kind==JournalKind.RuntimePrepared || records[index].Kind==JournalKind.RuntimeActivated || records[index].Kind==JournalKind.RuntimeCancelled ||
                    records[index].Kind==JournalKind.FileEnrolled || records[index].Kind==JournalKind.FileEnrollmentRevoked) continue;
                JournalEntry record=records[index];HostedWorkspacePreparation workspace=record.Kind==JournalKind.WorkspacePrepared?HostedWorkspacePreparation.Decode(record.Payload):null;
                HostedWorkspaceCompletion workspaceCompletion=record.Kind==JournalKind.WorkspaceObserved?HostedWorkspaceCompletion.Decode(record.Payload):null;
                DeploymentEvent value=workspace!=null?workspace.Admission:workspaceCompletion!=null?workspaceCompletion.Admission:DeploymentEvent.Decode(record.Payload);bool empty=value.Controller==0 && value.ObservationSha256==new string('0',64);
                switch(record.Kind) {
                    case JournalKind.ImportPrepared:
                    case JournalKind.ActivationPrepared:
                    case JournalKind.ComputePrepared:
                    case JournalKind.InferencePrepared:
                    case JournalKind.WorkspacePrepared:
                        if(state.Pending!=null || !empty || !state.generations.Add(value.Generation) ||
                            (record.Kind==JournalKind.ImportPrepared)!=(value.Purpose==1) ||
                            (record.Kind==JournalKind.ComputePrepared)!=(value.Purpose==3) ||
                            (record.Kind==JournalKind.InferencePrepared)!=(value.Purpose==4) ||
                            (record.Kind==JournalKind.WorkspacePrepared)!=(value.Purpose==5)) throw new SecurityException("Deployment admission is concurrent, replayed or not exact.");
                        if(value.Purpose>=3) {
                            if(state.Active==null || value.ReleaseSequence!=state.Active.ReleaseSequence || value.ReleaseSha256!=state.Active.ReleaseSha256 || value.PackageLeaf!=state.Active.PackageLeaf)
                                throw new SecurityException("Compute admission requires the exact genuinely activated immutable distribution, not an imported or substituted slot.");
                        } else if(value.ReleaseSequence!=(state.Active==null?1:checked(state.Active.ReleaseSequence+1))) throw new SecurityException("Release does not extend the current activation floor.");
                        if(value.Purpose==1 && state.imported.ContainsKey(value.ReleaseSha256)) throw new SecurityException("Exact release was already imported.");
                        if(value.Purpose==2) {
                            DeploymentEvent prior=state.Imported(value.ReleaseSha256);
                            if(prior==null || prior.ReleaseSequence!=value.ReleaseSequence || prior.PackageLeaf!=value.PackageLeaf) throw new SecurityException("Activation lacks a genuine exact imported package.");
                        }
                        if(workspace!=null) {
                            HostedWorkspaceAccountState prior=state.Workspace(value.ReleaseSha256);
                            if(workspace.Operation==1) {
                                if(prior!=null) throw new SecurityException("First account is already reserved; use explicit exact interruption repair.");
                                state.workspaces.Add(value.ReleaseSha256,new HostedWorkspaceAccountState(workspace.Original));
                            } else if(prior==null || prior.Original.RequestSha256!=workspace.Original.RequestSha256)
                                throw new SecurityException("Workspace challenge cannot adopt an unjournaled account generation.");
                            state.Workspace(value.ReleaseSha256).Admit(workspace);
                            state.PendingWorkspace=workspace;
                        }
                        state.Pending=value;state.CompletedControllers=0;state.SuccessfulControllers=0;state.LastSuccess=null;state.LastControllerRequestSha256=null;break;
                    case JournalKind.ControllerStarted:
                        if(state.Pending==null || !state.Pending.SameAdmission(value) || state.Worker!=null || value.Controller<4 || value.ObservationKind!=0 || state.CompletedControllers>=4 ||
                            (value.Purpose>=3 && value.ObservationSha256!=new string('0',64) && value.ObservationSha256!=value.Generation) || (value.Purpose==5 && value.ObservationSha256!=value.Generation) ||
                            ((value.Purpose==1 || value.Purpose>=3) && state.CompletedControllers!=0))
                            throw new SecurityException("Controller start is unadmitted, substituted or exceeds the finite profile.");
                        state.Worker=value;state.LastControllerRequestSha256=value.ObservationSha256==new string('0',64)?null:value.ObservationSha256;break;
                    case JournalKind.ControllerCompleted:
                        if(state.Pending==null || state.Worker==null || !state.Pending.SameAdmission(value) || value.Controller!=state.Worker.Controller ||
                            value.ControllerCreation!=state.Worker.ControllerCreation || value.ObservationKind==0 || value.ObservationSha256==new string('0',64)) throw new SecurityException("Controller completion lacks exact start or observed result.");
                        state.Worker=null;state.CompletedControllers++;if(value.ObservationKind==1) {state.SuccessfulControllers++;state.LastSuccess=value;}break;
                    case JournalKind.Imported:
                    case JournalKind.Activated:
                    case JournalKind.ComputeObserved:
                    case JournalKind.InferenceObserved:
                    case JournalKind.WorkspaceObserved:
                        if(state.Pending==null || !state.Pending.SameAdmission(value) || state.Worker!=null || state.SuccessfulControllers<1 || state.LastSuccess==null || value.Controller!=0 ||
                            value.ObservationKind!=1 || value.ObservationSha256!=state.LastSuccess.ObservationSha256 || (record.Kind==JournalKind.Imported)!=(value.Purpose==1) ||
                            (record.Kind==JournalKind.ComputeObserved)!=(value.Purpose==3) ||
                            (record.Kind==JournalKind.InferenceObserved)!=(value.Purpose==4) ||
                            (record.Kind==JournalKind.WorkspaceObserved)!=(value.Purpose==5)) throw new SecurityException("Deployment completion lacks successful observed controllers or the exact admission/result.");
                        if(workspaceCompletion!=null) {
                            if(state.PendingWorkspace==null) throw new SecurityException("Workspace completion lacks its protected original intent.");
                            state.Workspace(value.ReleaseSha256).Complete(state.PendingWorkspace,workspaceCompletion);state.PendingWorkspace=null;
                        }
                        if(value.Purpose==1) state.imported.Add(value.ReleaseSha256,value);else if(value.Purpose==2) state.Active=value;
                        state.Pending=null;state.CompletedControllers=0;state.SuccessfulControllers=0;state.LastSuccess=null;state.LastControllerRequestSha256=null;break;
                    case JournalKind.Cancelled:
                        if(state.Pending==null || !state.Pending.SameAdmission(value) || state.Worker!=null || value.Controller!=0 || value.ObservationKind!=2)
                            throw new SecurityException("Abandonment lacks a closed exact outstanding generation.");
                        if(state.PendingWorkspace!=null) {
                            if(state.PendingWorkspace.Operation==1 && state.CompletedControllers==0) state.workspaces.Remove(value.ReleaseSha256);
                            state.PendingWorkspace=null;
                        }
                        state.Pending=null;state.CompletedControllers=0;state.SuccessfulControllers=0;state.LastSuccess=null;state.LastControllerRequestSha256=null;break;
                    default:throw new SecurityException("Deployment journal contains an unsupported or unreviewed transition.");
                }
            }
            check();return state;
        }
    }
}
