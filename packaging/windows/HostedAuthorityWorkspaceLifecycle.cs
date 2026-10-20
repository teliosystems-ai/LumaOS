using System;
using System.IO;
using System.Security;
using System.Text;

namespace Luma.Windows.Hosted
{
    public sealed class HostedWorkspacePreparation
    {
        public DeploymentEvent Admission {get;private set;}
        public GuestWorkspaceRequest Request {get;private set;}
        public GuestWorkspaceRequest Original {get;private set;}
        public byte Operation {get;private set;}
        private readonly byte[] proof,signature;
        public HostedWorkspacePreparation(DeploymentEvent admission,GuestWorkspaceRequest request,GuestWorkspaceRequest original,byte operation,byte[] proof,byte[] signature)
        {
            if(admission==null || request==null || original==null || operation<1 || operation>3 || admission.Purpose!=5 || admission.Controller!=0 || admission.ObservationKind!=0 ||
                admission.ObservationSha256!=new string('0',64) || admission.Generation!=request.RequestSha256 || admission.ReleaseSha256!=request.ReleaseSha256 || request.Bytes.Length>1024 || original.Bytes.Length>1024)
                throw new SecurityException("Workspace admission must reserve one exact original public request before any effect.");
            if(operation==1) {if(!Wire.Equal(request.Bytes,original.Bytes)) throw new SecurityException("First bootstrap cannot adopt an earlier account intent.");}
            else request.RequireOriginal(original,original.RequestSha256);
            if(request.ProfileSha256!=Wire.Hash(GuestWorkspaceRequest.ExpectedProfile(request.RuntimeManifestSha256)) || operation==3 && !request.WithinPasswordAge(original))
                throw new SecurityException("Workspace intent changes its fixed publisher policy or attempts expired-password interruption recovery.");
            this.proof=Wire.Copy(proof,1,512);this.signature=Wire.Copy(signature,64,64);
            TimeAttestation time=TimeAttestation.Decode(this.proof);
            if(Wire.Hash(this.proof)!=request.UtcProofSha256 || time.Installation!=request.Installation || time.ReleaseSha256!=request.ReleaseSha256 ||
                time.LowerMilliseconds/86400000UL!=request.ProtectedUtcDay || time.UpperMilliseconds/86400000UL!=request.ProtectedUtcDay)
                throw new SecurityException("Workspace request does not bind its exact independent UTC proof/day.");
            Admission=admission;Request=request;Original=original;Operation=operation;
        }
        public void RequireIdentity(AuthorityIdentity identity,string actor)
        {
            if(identity==null || actor!=identity.FirstAdminSid || Request.Installation!=identity.Installation || Request.ActorSidSha256!=Wire.Hash(Encoding.ASCII.GetBytes(actor)))
                throw new SecurityException("Workspace intent is not bound to the actual commissioned original Windows Admin.");
        }
        internal void RequireChronologicalUtc(AuthorityIdentity identity)
        {LiveUtcWindow.Validate(identity,Request.ReleaseSha256,1,4102444800000UL,TimeAttestation.Decode(proof),signature);}
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-workspace-prepared-v1")) {
                writer.Blob(Admission.Encode(),512);writer.U8(Operation);writer.Blob(Request.Bytes,1024);writer.Blob(Original.Bytes,1024);writer.Blob(proof,512);writer.Fixed(signature,64);return writer.Bytes();
            }
        }
        public static HostedWorkspacePreparation Decode(byte[] bytes)
        {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-workspace-prepared-v1")) {
                DeploymentEvent admission=DeploymentEvent.Decode(reader.Blob(512));byte operation=reader.U8();GuestWorkspaceRequest request=GuestWorkspaceRequest.Decode(reader.Blob(1024)),original=GuestWorkspaceRequest.Decode(reader.Blob(1024));
                HostedWorkspacePreparation result=new HostedWorkspacePreparation(admission,request,original,operation,reader.Blob(512),reader.Fixed(64));reader.End();if(!Wire.Equal(result.Encode(),bytes)) throw new SecurityException("Noncanonical workspace preparation.");return result;
            }
        }
    }
    public sealed class HostedWorkspaceCompletion
    {
        public DeploymentEvent Admission {get;private set;}
        public byte Operation {get;private set;}
        private readonly byte[] observation;
        public byte[] Observation {get{return (byte[])observation.Clone();}}
        public HostedWorkspaceCompletion(DeploymentEvent admission,byte operation,byte[] observation)
        {
            if(admission==null || admission.Purpose!=5 || admission.Controller!=0 || admission.ObservationKind!=1 || operation<1 || operation>3 || observation==null || observation.Length>2048 ||
                (operation==2)!=(observation.Length>0)) throw new SecurityException("Workspace completion must bind its distinct console or health outcome.");
            Admission=admission;Operation=operation;this.observation=(byte[])observation.Clone();
            if(operation==2 && Wire.Hash(observation)!=admission.ObservationSha256) throw new SecurityException("Workspace health bytes differ from the exact completed controller observation.");
        }
        public byte[] Encode()
        {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-workspace-observed-v1")) {writer.Blob(Admission.Encode(),512);writer.U8(Operation);writer.Blob(observation,2048);return writer.Bytes();}}
        public static HostedWorkspaceCompletion Decode(byte[] bytes)
        {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-workspace-observed-v1")) {HostedWorkspaceCompletion result=new HostedWorkspaceCompletion(DeploymentEvent.Decode(reader.Blob(512)),reader.U8(),reader.Blob(2048));reader.End();if(!Wire.Equal(result.Encode(),bytes)) throw new SecurityException("Noncanonical workspace completion.");return result;}
        }
    }
    public sealed class HostedWorkspaceAccountState
    {
        public GuestWorkspaceRequest Original {get;private set;}
        public bool ConsoleCompleted {get;private set;}
        public bool ManualHealthReady {get;private set;}
        public uint LastProtectedUtcDay {get;private set;}
        internal string AccountStateSha256;
        internal HostedWorkspaceAccountState(GuestWorkspaceRequest original) {Original=original;LastProtectedUtcDay=original.ProtectedUtcDay;}
        internal void Admit(HostedWorkspacePreparation preparation)
        {
            if(preparation.Original.RequestSha256!=Original.RequestSha256 || preparation.Request.ProtectedUtcDay<LastProtectedUtcDay)
                throw new SecurityException("Workspace aging cannot roll protected UTC behind a previously journaled account admission.");
            LastProtectedUtcDay=preparation.Request.ProtectedUtcDay;
        }
        internal void Complete(HostedWorkspacePreparation prepared,HostedWorkspaceCompletion completed)
        {
            if(prepared.Operation!=completed.Operation || prepared.Original.RequestSha256!=Original.RequestSha256)
                throw new SecurityException("Workspace completion changed original account generation or operation.");
            if(completed.Operation!=2) {ConsoleCompleted=true;ManualHealthReady=false;return;}
            GuestWorkspaceObservation observation=GuestWorkspaceObservation.Validate(prepared.Request,Original,completed.Observation);
            if(AccountStateSha256!=null && observation.AccountFilesComplete && AccountStateSha256!=observation.AccountStateSha256)
                throw new SecurityException("Guest credential/account closure changed after protected Windows observation; separately governed recovery is required.");
            if(observation.AccountFilesComplete) AccountStateSha256=observation.AccountStateSha256;
            ManualHealthReady=ConsoleCompleted && observation.AccountFilesComplete && observation.BootstrapPamVerifiedOnce && observation.PasswordAgeWithin90Days;
        }
    }
}
