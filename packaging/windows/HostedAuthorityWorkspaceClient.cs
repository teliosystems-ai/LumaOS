using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Luma.Windows.Hosted
{
    public static class HostedWorkspaceReview
    {
        public static HostedWorkspacePreparation Validate(byte[] exact,byte operation,string release,string login,string nonce,string actualSid)
        {
            using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-workspace-review-v1")) {
                HostedWorkspacePreparation prepared=HostedWorkspacePreparation.Decode(reader.Blob(4096));Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);reader.End();
                if(prepared.Operation!=operation || prepared.Request.ReleaseSha256!=release || prepared.Request.Login!=login || prepared.Request.Nonce!=nonce ||
                    prepared.Request.ActorSidSha256!=Wire.Hash(Encoding.ASCII.GetBytes(Wire.Sid(actualSid)))) throw new SecurityException("Workspace review substituted original selected operation/release/login/client nonce or actual Windows actor.");
                return prepared;
            }
        }
    }
    internal static partial class HostedAuthorityProgram
    {
        private static int WorkspaceClient(string[] arguments)
        {
            if(arguments==null || arguments.Length!=3 || Console.IsInputRedirected || Console.IsOutputRedirected) throw new SecurityException("Interactive workspace-setup|workspace-health|workspace-open|workspace-repair RELEASE_SHA256 LOGIN, or workspace-recover RELEASE_SHA256 GENERATION required.");
            string command=arguments[0];bool open=command=="workspace-open",recovery=command=="workspace-recover";
            byte operation=command=="workspace-setup"?(byte)1:command=="workspace-health" || open?(byte)2:command=="workspace-repair"?(byte)3:(byte)0;
            if(!recovery && operation==0) throw new SecurityException("Workspace client operation is not closed.");Wire.Bytes(arguments[1],32,true);
            if(recovery) Wire.Bytes(arguments[2],32,true);else if(!GuestWorkspaceRequest.CanonicalLogin(arguments[2])) throw new SecurityException("Exact nonroot login differs.");
            string selected=open?"workspace-health":command,nonce=Wire.Hex(Wire.Random(32));bool ready=false;int cancelled=0;
            ConsoleCancelEventHandler cancel=delegate(object sender,ConsoleCancelEventArgs args) {Interlocked.Exchange(ref cancelled,1);args.Cancel=true;};Console.CancelKeyPress+=cancel;
            try {using(HostedClientIdentity actor=new HostedClientIdentity())
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",HostedPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)) {
                Stopwatch age=Stopwatch.StartNew();Action check=delegate {actor.Check();if(Interlocked.CompareExchange(ref cancelled,0,0)!=0) throw new OperationCanceledException("Workspace cancelled; uncertain account generation remains fenced for explicit recovery.");if(age.Elapsed>=TimeSpan.FromSeconds(30)) throw new SecurityException("Original thirty-second workspace purpose expired; no automatic retry or secret replay.");HostedPipe.CheckServer(pipe);};
                actor.Check();pipe.Connect(3000);check();IngestionHello(pipe,check);
                using(Wire.Writer request=new Wire.Writer("luma-windows-hosted-request-v1")) {request.Text(selected,32);request.Fixed(Wire.Bytes(arguments[1],32,true),32);if(recovery) request.Fixed(Wire.Bytes(arguments[2],32,true),32);else {request.Text(arguments[2],31);request.Fixed(Wire.Bytes(nonce,32,true),32);}HostedPipe.Write(pipe,request.Bytes(),check,TimeSpan.FromSeconds(30));}
                HostedWorkspacePreparation reviewed=null;bool confirmed=false;
                while(true) {
                    byte[] response=HostedPipe.Read(pipe,check,TimeSpan.FromSeconds(30));try {using(Wire.Reader frame=new Wire.Reader(response,"luma-windows-hosted-response-v1")) {
                        string kind=frame.Text(32);byte[] payload=frame.Blob(60000);frame.End();try {
                            if(kind=="refused") throw new SecurityException("Actual workspace operation refused; preserve any outstanding resource/account state. No installation or qualification is inferred.");
                            if(kind=="utc-challenge") {HostedTimeEndpoint.Deliver(pipe,payload,arguments[1],check);continue;}
                            if(kind=="review") {
                                if(confirmed) throw new SecurityException("A workspace purpose cannot receive a second review/controller ceremony.");
                                string hash=Wire.Hash(payload);using(Wire.Reader review=new Wire.Reader(payload,"luma-windows-hosted-reviewed-action-v1")) {
                                    if(review.Text(32)!=selected) throw new SecurityException("Workspace review changed original operation.");review.Fixed(32);byte[] exact=review.Blob(8192);string detail=review.Text(16000);review.End();
                                    if(recovery) {using(Wire.Reader recoveryReview=new Wire.Reader(exact,"luma-windows-hosted-workspace-recovery-v1")) {DeploymentEvent admission=DeploymentEvent.Decode(recoveryReview.Blob(512));if(admission.Purpose!=5 || admission.ReleaseSha256!=arguments[1] || admission.Generation!=arguments[2] || admission.Controller!=0 || admission.ObservationKind!=0) throw new SecurityException("Workspace recovery review changed exact pending generation.");Wire.Bytes(Wire.Hex(recoveryReview.Fixed(32)),32,true);recoveryReview.End();}}
                                    else reviewed=HostedWorkspaceReview.Validate(exact,operation,arguments[1],arguments[2],nonce,actor.Sid);
                                    Console.WriteLine(detail);
                                }
                                Console.WriteLine("Confirm only this exact action: CONFIRM "+hash);
                                if(IngestionLine(check,age,TimeSpan.FromSeconds(30))!="CONFIRM "+hash) throw new OperationCanceledException("Workspace review was not confirmed; no new account controller admitted.");
                                using(Wire.Writer confirmation=new Wire.Writer("luma-windows-hosted-confirm-v1")) {confirmation.Fixed(Wire.Bytes(hash,32,true),32);HostedPipe.Write(pipe,confirmation.Bytes(),check,TimeSpan.FromSeconds(30));}confirmed=true;continue;
                            }
                            if(kind=="workspace-recovered") {
                                if(!recovery || !confirmed) throw new SecurityException("Workspace cancellation crossed another original purpose.");
                                using(Wire.Reader receipt=new Wire.Reader(payload,"luma-windows-hosted-workspace-recovered-v1")) {if(Wire.Hex(receipt.Fixed(32))!=arguments[1] || Wire.Hex(receipt.Fixed(32))!=arguments[2]) throw new SecurityException("Workspace cancellation substituted release/generation.");Wire.Bytes(Wire.Hex(receipt.Fixed(32)),32,true);if(receipt.U8()!=0 || receipt.U8()!=0) throw new SecurityException("Cancellation cannot claim account completion/qualification.");receipt.End();}
                                Console.WriteLine("Exact original-controller exit and confined request revocation/drain observed. No account retry/adoption; use a separate explicit repair if original execution began.");return 0;
                            }
                            if(kind!="workspace-completed" || recovery || !confirmed || reviewed==null) throw new SecurityException("Unexpected response cannot complete first-launch or health.");
                            using(Wire.Reader receipt=new Wire.Reader(payload,"luma-windows-hosted-workspace-result-v1")) {
                                if(Wire.Hex(receipt.Fixed(32))!=reviewed.Request.RequestSha256 || Wire.Hex(receipt.Fixed(32))!=reviewed.Original.RequestSha256 || receipt.U8()!=operation) throw new SecurityException("Workspace receipt substituted original account/request/operation.");
                                Wire.Bytes(Wire.Hex(receipt.Fixed(32)),32,true);byte console=receipt.U8(),health=receipt.U8();byte[] metadata=receipt.Blob(2048);
                                if(console>1 || health>1 || health==1 && console!=1 || receipt.U8()!=0 || receipt.U8()!=0) throw new SecurityException("Workspace receipt claims unavailable grant/qualification or contradictory state.");receipt.End();
                                if(operation==2) {GuestWorkspaceObservation observed=GuestWorkspaceObservation.Validate(reviewed.Request,reviewed.Original,metadata);if(health==1 && (!observed.AccountFilesComplete || !observed.BootstrapPamVerifiedOnce || !observed.PasswordAgeWithin90Days)) throw new SecurityException("Manual health readiness contradicts actual account observation.");}
                                else if(metadata.Length!=0 || health!=0 || console!=1) throw new SecurityException("Console completion is not a fresh independent health observation.");ready=health==1;
                            }
                            check();Console.WriteLine(operation==2?(ready?"Fresh challenge-bound account/runtime/UTC health joined to protected Windows history. Manual workspace available; model not requested, no native product grant bridge or production qualification.":"Health observation completed but account/PAM-once/aging/manual readiness is incomplete; no grant or qualification. Explicit recovery may be required."):"Original owned console exited and exact guest request drainage completed. Account ceremony closed; run a fresh workspace-health before opening manual workspace.");break;
                        }finally {Array.Clear(payload,0,payload.Length);}
                    }}finally {Array.Clear(response,0,response.Length);}
                }
            }}finally {Console.CancelKeyPress-=cancel;}
            if(open) {if(!ready) throw new SecurityException("Manual launcher refuses incomplete account health.");return WorkspaceManual(arguments[1],arguments[2]);}return 0;
        }
        private static string WorkspaceLine(string label)
        {Console.Write(label+": ");string value=Console.ReadLine();if(value==null || value.Length>4096 || value.IndexOf('\0')>=0) throw new SecurityException("Manual selection is absent or exceeds its bounded text field.");return value;}
        private static int WorkspaceManual(string release,string login)
        {
            // This menu holds no resource lease or user grant while idle. Each
            // selected action constructs a NEW authenticated bounded ceremony.
            using(HostedClientIdentity actor=new HostedClientIdentity()) while(true) {
                actor.Check();Console.WriteLine("Manual workspace (model disabled/not requested). Independent Windows original-user operations; no Linux product grant.\n1 Read exact scoped snapshot\n2 Save completed scoped snapshot to new protected NTFS file\n3 Authenticated diagnostics\n4 Explicit account interruption repair\n5 Fresh health\n0 Cancel/close");
                string choice=WorkspaceLine("Choice");actor.Check();if(choice=="0") return 0;
                if(choice=="3") {Client(new string[]{"status","host-deployment"});continue;}
                if(choice=="4") {WorkspaceClient(new string[]{"workspace-repair",release,login});continue;}
                if(choice=="5") {WorkspaceClient(new string[]{"workspace-health",release,login});continue;}
                if(choice=="1" || choice=="2") {
                    string[] read=new string[choice=="1"?6:7];read[0]=choice=="1"?"read-enrolled-file":"save-enrolled-snapshot";
                    read[1]=WorkspaceLine("Exact installation SHA256");read[2]=WorkspaceLine("Held source root (absolute)");read[3]=WorkspaceLine("Exact relative source path");read[4]=WorkspaceLine("Exact source bytes (1..1048576)");read[5]=WorkspaceLine("Whole source SHA256");if(choice=="2") read[6]=WorkspaceLine("New exclusive protected NTFS target (absolute)");
                    actor.Check();if(choice=="1") Client(read);else ManualSaveClient(read);continue;
                }
                Console.WriteLine("No action dispatched; choose a listed operation.");
            }
        }
    }
}
