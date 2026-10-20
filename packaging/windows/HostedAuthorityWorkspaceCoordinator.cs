using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Text;

namespace Luma.Windows.Hosted
{
    internal static partial class HostedCoordinator
    {
        private static void WorkspaceActive(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running,byte operation)
        {
            string releaseHash=Wire.Hex(input.Fixed(32)),login=input.Text(31),nonce=Wire.Hex(input.Fixed(32));input.End();Wire.Bytes(releaseHash,32,true);Wire.Bytes(nonce,32,true);
            if(operation<1 || operation>3 || !GuestWorkspaceRequest.CanonicalLogin(login)) throw new SecurityException("Workspace operation or exact nonroot login differs.");
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(history,original);
                if(state.Pending!=null || state.Active==null || state.Active.ReleaseSha256!=releaseHash) throw new SecurityException("First-launch requires the exact activated release and no outstanding controller/resource generation.");
                HostedWorkspaceAccountState account=state.Workspace(releaseHash);
                if((operation==1)!=(account==null) || account!=null && account.Original.Login!=login) throw new SecurityException("Account is reserved by its protected original intent; inspect or explicitly repair that exact login, never adopt or recreate it.");
                HostedComputeContract.RequireAdmissionCapacity(history);authority.State.RequireReadableTail();AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,state.Active,out signature);release.Verify(authority.Trust.ForRelease(),signature);
                string runtime=null,profile=null;foreach(Luma.Windows.RequiredFile file in release.RequiredFiles) {if(file.Path==GuestWorkspaceRequest.RuntimePath) runtime=file.Sha256;if(file.Path==GuestWorkspaceRequest.ProfilePath) profile=file.Sha256;}
                if(runtime==null || profile==null) throw new SecurityException("Active package is not the distinct publisher-bound workspace profile.");
                HostedReleaseLease utc=new HostedReleaseLease(pipe,authority,release,signature,original);utc.Check();HostedWorkspaceTime time=utc.WorkspaceTime();
                GuestWorkspaceRequest request=GuestWorkspaceRequest.Challenge(authority.Identity.Installation,releaseHash,runtime,profile,Wire.Hash(Encoding.ASCII.GetBytes(actor.Sid)),login,time.Day,Wire.Hash(time.Proof),nonce);
                request.RequireRelease(release);GuestWorkspaceRequest bootstrap=account==null?request:account.Original;
                if(account!=null && request.ProtectedUtcDay<account.LastProtectedUtcDay) throw new SecurityException("Fresh UTC cannot roll account aging behind a previous protected admission.");
                if(operation!=1) request.RequireOriginal(bootstrap,bootstrap.RequestSha256);
                if(operation==3 && !request.WithinPasswordAge(bootstrap)) throw new SecurityException("Explicit interruption repair does not reset or extend the original ninety-day password age; separately governed password recovery is required.");
                state.RequireFreshGeneration(request.RequestSha256);
                DeploymentEvent admission=new DeploymentEvent(5,releaseHash,release.Sequence,request.RequestSha256,HostedHostResources.BootCreation(),state.Active.PackageLeaf,0,0,0,new string('0',64));
                HostedWorkspacePreparation prepared=new HostedWorkspacePreparation(admission,request,bootstrap,operation,time.Proof,time.Signature);prepared.RequireIdentity(authority.Identity,actor.Sid);
                string action=operation==1?"workspace-setup":operation==2?"workspace-health":"workspace-repair";
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-workspace-review-v1")) {
                    exact.Blob(prepared.Encode(),4096);exact.Fixed(Wire.Bytes(history.Head,32,true),32);
                    Review(pipe,action,exact.Bytes(),"Separate original Windows first-Admin workspace purpose; maximum thirty seconds INCLUDING this review, UTC delivery, controller, private account transition and drainage. No automatic extension.\nExact new nonroot Linux account: "+login+" UID/GID1000, generation1. Windows Admin custody is separate; the Linux user receives no sudo/root/product Admin role.\nOriginal account request: "+bootstrap.RequestSha256+"\nCurrent challenge/resource: "+request.RequestSha256+"\nRelease: "+releaseHash+"\nProtected password-aging day: "+bootstrap.ProtectedUtcDay+"; maximum90days, never reset by interruption repair.\n"+
                        (operation==2?"Read-only guest health observation: exact account files, original bootstrap marker and fresh actor/release/runtime/UTC challenge. Historical PAM verification is not a renewed user grant. Model execution is not required. No native TPM/content grant bridge is available in this hosted profile.":"After explicit confirmation an OWNED NEW CONSOLE opens for hidden local Linux password entry and independent real PAM. No credential, password verifier or credential witness enters argv, manifests, logs or this review. Closing/cancelling may leave the exact private account transaction for a separately reviewed repair, never guessed account adoption. Repair can initialize a never-started original intent only with all original empty baselines and absent home/stage; partial malformed stages remain retained/refused.")+
                        "\nGuest256MiB/no swap/8tasks/1CPU/25CPU-seconds; Windows/guest require observed1.25GiB startup headroom and1GiB continuous floor, not an atomic reservation or no-impact guarantee. Private NTFS host protection and unmanaged policy must remain admissible for new writes; sampled checks do not erase exposure if protection changes between samples. Original-controller exit and durable exact-request revocation plus no queued guest job and empty/inactive cgroup are mandatory. No production qualification.",utc.CheckObserved);
                }
                HostedProtectionLease protection=new HostedProtectionLease(authority.State,actor,original);HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());
                Action writing=delegate {original();authority.State.Check();protection.Check();utc.CheckObserved();if(utc.WorkspaceTime().Day!=request.ProtectedUtcDay) throw new SecurityException("Protected UTC crossed the exact reviewed aging day.");HostedHostResources.Check(1024UL*1024*1024);};
                Action observed=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action live=delegate {original();authority.State.Check();utc.Check();observed();};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);observed();};
                Action starting=delegate {live();protection.CheckFresh();HostedHostResources.Check(1280UL*1024*1024);};
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);starting();append(JournalKind.WorkspacePrepared,prepared.Encode());DeploymentEvent started=null;
                    byte[] metadata=HostedWorkspaceRunner.Execute(execution,actor,prepared,delegate(OwnedWindowsProcess controller) {
                        starting();if(started!=null) throw new SecurityException("One workspace purpose cannot dispatch a second controller.");started=admission.WithController(controller.Id,controller.Creation,0,request.RequestSha256);append(JournalKind.ControllerStarted,started.Encode());starting();
                    },live);
                    live();directory.Check();if(started==null || !OwnedWindowsProcess.OriginalExited(started.Controller,started.ControllerCreation)) throw new SecurityException("Original interactive workspace controller exit is unobserved.");
                    string digest=operation==2?Wire.Hash(metadata):Wire.Hash(Encoding.ASCII.GetBytes("luma-workspace-original-console-exit-and-confined-drain-v1\n"+request.RequestSha256+"\n"+bootstrap.RequestSha256+"\n"));
                    append(JournalKind.ControllerCompleted,started.WithController(started.Controller,started.ControllerCreation,1,digest).Encode());
                    append(JournalKind.WorkspaceObserved,new HostedWorkspaceCompletion(admission.WithController(0,0,1,digest),operation,metadata).Encode());
                    JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory final=DeploymentHistory.Replay(completed,live);HostedWorkspaceAccountState closed=final.Workspace(releaseHash);
                    if(final.Pending!=null || closed==null || closed.Original.RequestSha256!=bootstrap.RequestSha256) throw new SecurityException("Workspace completion lacks exact protected account state.");
                    using(Wire.Writer receipt=new Wire.Writer("luma-windows-hosted-workspace-result-v1")) {receipt.Fixed(Wire.Bytes(request.RequestSha256,32,true),32);receipt.Fixed(Wire.Bytes(bootstrap.RequestSha256,32,true),32);receipt.U8(operation);receipt.Fixed(Wire.Bytes(completed.Head,32,true),32);receipt.U8(closed.ConsoleCompleted?(byte)1:(byte)0);receipt.U8(closed.ManualHealthReady?(byte)1:(byte)0);receipt.Blob(metadata,2048);receipt.U8(0);receipt.U8(0);Reply(pipe,"workspace-completed",receipt.Bytes(),live);}
                }
            }
        }
        private static void RecoverWorkspace(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running)
        {
            string releaseHash=Wire.Hex(input.Fixed(32)),generation=Wire.Hex(input.Fixed(32));input.End();Wire.Bytes(releaseHash,32,true);Wire.Bytes(generation,32,true);Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,RuntimeAccess.Standard,true)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(history,original);DeploymentEvent admission=state.Pending;
                if(admission==null || admission.Purpose!=5 || state.PendingWorkspace==null || admission.ReleaseSha256!=releaseHash || admission.Generation!=generation) throw new SecurityException("Workspace cancellation requires its exact outstanding account generation; never replay a secret ceremony.");
                string drain=state.DrainRequestSha256();byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,admission,out signature);AuthorityIdentity verifier=authority.Trust.ForCleanup(generation);release.Verify(verifier,signature);
                HostedReleaseLease utc=HostedReleaseLease.ForAbandonment(pipe,authority,release,signature,original,verifier);utc.Check();
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-workspace-recovery-v1")) {exact.Blob(admission.Encode(),512);exact.Fixed(Wire.Bytes(history.Head,32,true),32);Review(pipe,"workspace-recover",exact.Bytes(),"Close only exact interrupted workspace resource "+generation+" after original controller exit and fresh confined request-revocation/drain. No password prompt, account adoption, automatic repair/retry, distribution deletion or process-name kill. Any started original account intent remains reserved; a separate fresh explicit repair can inspect its exact account transition. No user grant or production qualification.",utc.CheckObserved);}
                HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());Action writing=delegate {original();authority.State.Check();utc.CheckObserved();};Action live=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);live();};AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);if(state.Worker!=null && !OwnedWindowsProcess.OriginalExited(state.Worker.Controller,state.Worker.ControllerCreation)) throw new SecurityException("Original workspace console remains alive; no resource release.");
                    HostedWorkspaceRunner.Drain(execution,actor,admission,drain,live);directory.Check();live();string proof=Wire.Hash(Encoding.ASCII.GetBytes("luma-workspace-drain-without-secret-replay-v1\n"+generation+"\n"));
                    if(state.Worker!=null) append(JournalKind.ControllerCompleted,state.Worker.WithController(state.Worker.Controller,state.Worker.ControllerCreation,2,proof).Encode());append(JournalKind.Cancelled,admission.WithController(0,0,2,proof).Encode());
                    JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());if(DeploymentHistory.Replay(completed,live).Pending!=null) throw new SecurityException("Workspace cancellation retained an outstanding controller.");
                    using(Wire.Writer receipt=new Wire.Writer("luma-windows-hosted-workspace-recovered-v1")) {receipt.Fixed(Wire.Bytes(releaseHash,32,true),32);receipt.Fixed(Wire.Bytes(generation,32,true),32);receipt.Fixed(Wire.Bytes(completed.Head,32,true),32);receipt.U8(0);receipt.U8(0);Reply(pipe,"workspace-recovered",receipt.Bytes(),live);}
                }
            }
        }
    }
}
