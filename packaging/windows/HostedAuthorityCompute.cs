using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Luma.Windows.Hosted
{
    // This is a bounded inert compute bridge, not a product-principal, finite
    // grant, inference or publication authority. The actual original first
    // Admin and current authenticated distribution are mandatory at runtime.
    public static class HostedComputeContract
    {
        public const int MaximumPayloadBytes=4096,MaximumRequestBytes=8192;
        public static GuestComputeRequest Decode(byte[] bytes)
        {
            GuestComputeRequest request=GuestComputeRequest.Decode(Wire.Copy(bytes,1,MaximumRequestBytes));
            if(request.PayloadBytes>MaximumPayloadBytes) throw new SecurityException("Original compute payload exceeds the fixed4096-byte UTF8 admission budget.");
            return request;
        }
        public static void RequireAdmissionCapacity(JournalHistory history)
        {
            if(history==null || history.FileEnrollments==null) throw new ArgumentNullException("history");
            long bytes=0;foreach(JournalEntry entry in history.Entries) bytes=checked(bytes+entry.Bytes.Length);
            int fileTail=history.FileEnrollments.ActiveCount+history.FileEnrollments.AbortReserveCredits;
            // Prepare/start/complete/observed plus bounded interrupted-write
            // repair room. This is logical journal headroom, not a claim that
            // unrelated trusted Windows writers cannot exhaust the volume.
            const ulong computeEvents=8;
            if(history.Sequence+computeEvents+(ulong)fileTail>HostedJournalCapacity.MaximumEvents ||
                bytes+checked(((long)computeEvents+fileTail)*HostedJournalCapacity.ReservedEventBytes)>HostedJournalCapacity.MaximumJournalBytes)
                throw new SecurityException("Compute requires its complete finite journal/recovery headroom before creating a resource generation.");
        }
        public static byte[] ReviewBytes(DeploymentEvent admission,GuestComputeRequest request,string head)
        {
            if(admission==null || request==null || admission.Purpose!=3 || admission.Generation!=request.RequestSha256 || admission.Controller!=0 || admission.ObservationKind!=0)
                throw new SecurityException("Compute review must bind the exact unexecuted request generation.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-compute-review-v1")) {
                writer.Blob(admission.Encode(),4096);writer.Text(request.Operation,32);writer.Fixed(Wire.Bytes(request.PayloadSha256,32,true),32);
                writer.Fixed(Wire.Bytes(head,32,true),32);return writer.Bytes();
            }
        }
        public static DeploymentEvent ValidateReview(byte[] exact,GuestComputeRequest request,string release)
        {
            if(request==null) throw new ArgumentNullException("request");Wire.Bytes(release,32,true);
            using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-compute-review-v1")) {
                DeploymentEvent admission=DeploymentEvent.Decode(reader.Blob(4096));string operation=reader.Text(32),payload=Wire.Hex(reader.Fixed(32)),head=Wire.Hex(reader.Fixed(32));reader.End();
                if(admission.ReleaseSha256!=release || operation!=request.Operation || payload!=request.PayloadSha256 ||
                    !Wire.Equal(ReviewBytes(admission,request,head),exact)) throw new SecurityException("Service substituted the selected exact request, payload, active release or review.");
                return admission;
            }
        }
        public static string Digest(byte[] bytes) {if(bytes==null) throw new ArgumentNullException("bytes");using(SHA256 hash=SHA256.Create()) return Wire.Hex(hash.ComputeHash(bytes));}
    }

    public sealed class HostedComputeDelivery
    {
        private readonly string review,request,result;private readonly byte[] bytes;private int delivered,pending;
        public int Delivered {get{return delivered;}}public bool Complete {get{return delivered==bytes.Length && pending==0;}}
        public HostedComputeDelivery(string review,string request,byte[] bytes)
        {
            Wire.Bytes(review,32,true);Wire.Bytes(request,32,true);
            if(bytes==null || bytes.Length<1 || bytes.Length>GuestComputeRequest.MaximumResult) throw new SecurityException("Compute result exceeds the fixed complete delivery bound.");
            this.review=review;this.request=request;this.bytes=(byte[])bytes.Clone();result=HostedComputeContract.Digest(bytes);
        }
        public byte[] Next()
        {
            if(pending!=0 || Complete) throw new SecurityException("A result chunk is already pending or its exact delivery is complete.");
            pending=Math.Min(32768,bytes.Length-delivered);
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-compute-chunk-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.Fixed(Wire.Bytes(result,32,true),32);
                writer.U32((uint)bytes.Length);writer.U32((uint)delivered);byte[] part=new byte[pending];Buffer.BlockCopy(bytes,delivered,part,0,pending);
                try {writer.Blob(part,32768);return writer.Bytes();}finally {Array.Clear(part,0,part.Length);}
            }
        }
        public void Acknowledge(byte[] frame)
        {
            if(pending==0) throw new SecurityException("No exact compute chunk awaits acknowledgement.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-compute-ack-v1")) {
                int total=checked(delivered+pending);
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request || reader.U32()!=(uint)total) throw new SecurityException("Compute acknowledgement substituted review, request or cumulative offset.");
                byte[] digest;using(SHA256 hash=SHA256.Create()) digest=hash.ComputeHash(bytes,0,total);
                if(!Wire.Equal(reader.Fixed(32),digest)) throw new SecurityException("Compute acknowledgement omitted or changed delivered bytes.");reader.End();delivered=total;pending=0;
            }
        }
        public byte[] Receipt(string head)
        {
            if(!Complete) throw new SecurityException("Partial compute delivery has no complete receipt.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-compute-completed-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.Fixed(Wire.Bytes(result,32,true),32);
                writer.U32((uint)bytes.Length);writer.Fixed(Wire.Bytes(head,32,true),32);writer.U8(1);
                for(int index=0;index<6;index++) writer.U8(0);return writer.Bytes();
            }
        }
        public void Clear() {Array.Clear(bytes,0,bytes.Length);}
    }

    // Local continuity DATA only; the service supplies every actual NV read.
    // Only a genuinely signed exact next record can advance the expectation.
    public sealed class HostedComputeHead
    {
        private readonly AuthorityIdentity identity;private ulong sequence;private string record;
        public string Head {get;private set;}
        public HostedComputeHead(AuthorityIdentity identity,JournalHistory history,string observed)
        {
            if(identity==null || history==null) throw new ArgumentNullException("history");history.Reconcile(identity,null,observed);
            this.identity=identity;sequence=history.Sequence;record=history.Record;Head=history.Head;
        }
        public void Require(string observed) {Wire.Bytes(observed,32,true);if(observed!=Head) throw new SecurityException("Protected authority head changed during the exact original compute session; retain uncertain evidence and refuse new output.");}
        public void Advance(JournalEntry accepted)
        {
            if(accepted==null) throw new ArgumentNullException("accepted");JournalEntry exact=JournalEntry.Decode(identity,accepted.Bytes);
            if(exact.Sequence!=checked(sequence+1) || exact.PreviousHead!=Head || exact.PreviousRecord!=record) throw new SecurityException("Compute cannot adopt a stale, replayed, forked or different authority write as its next expected head.");
            sequence=exact.Sequence;record=exact.RecordSha256;Head=exact.NextHead;
        }
    }

    public sealed class HostedComputeReceiver : IDisposable
    {
        private readonly string request;private string review,result;private byte[] bytes;private int received;private bool completed;
        public bool Complete {get{return completed;}}
        public HostedComputeReceiver(string request) {Wire.Bytes(request,32,true);this.request=request;}
        public void Reviewed(string hash) {Wire.Bytes(hash,32,true);if(review!=null) throw new SecurityException("Compute cannot substitute a second interactive review.");review=hash;}
        public byte[] Part(byte[] frame)
        {
            if(review==null || completed) throw new SecurityException("Compute result crossed its original unreviewed or completed purpose.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-compute-chunk-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request) throw new SecurityException("Compute chunk substituted exact review/request.");
                string digest=Wire.Hex(reader.Fixed(32));Wire.Bytes(digest,32,true);uint length=reader.U32(),offset=reader.U32();byte[] part=reader.Blob(32768);reader.End();
                try {
                    if(length<1 || length>GuestComputeRequest.MaximumResult || offset!=(uint)received || part.Length!=Math.Min(32768,(long)length-received)) throw new SecurityException("Compute chunk exceeds its complete finite budget or exact offset.");
                    if(bytes==null) {bytes=new byte[length];result=digest;}else if(length!=bytes.Length || result!=digest) throw new SecurityException("Compute result changed complete digest or length during delivery.");
                    if(part.Length==0) throw new SecurityException("Empty post-completion compute chunk refused.");Buffer.BlockCopy(part,0,bytes,received,part.Length);received+=part.Length;
                }finally {Array.Clear(part,0,part.Length);}
            }
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-compute-ack-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.U32((uint)received);
                using(SHA256 hash=SHA256.Create()) writer.Fixed(hash.ComputeHash(bytes,0,received),32);return writer.Bytes();
            }
        }
        public void Finish(byte[] frame)
        {
            if(completed || review==null || bytes==null || received!=bytes.Length) throw new SecurityException("Partial or replayed compute result has no complete receipt.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-compute-completed-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request || Wire.Hex(reader.Fixed(32))!=result || reader.U32()!=received)
                    throw new SecurityException("Compute receipt substituted original reviewed request or complete result.");
                Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);if(reader.U8()!=1) throw new SecurityException("Compute receipt omits genuine completed delivery.");
                for(int index=0;index<6;index++) if(reader.U8()!=0) throw new SecurityException("Inert compute receipt claims unsupported principal, grant, inference, workflow, publication or qualification authority.");reader.End();
            }
            if(HostedComputeContract.Digest(bytes)!=result) throw new SecurityException("Original-client complete compute result hash differs.");completed=true;
        }
        public string ResultBase64() {if(!completed) throw new SecurityException("Uncompleted compute output cannot be exposed as a complete result.");return Convert.ToBase64String(bytes);}
        public string Summary() {if(!completed) throw new SecurityException("Compute result is incomplete.");return "Received "+received.ToString(CultureInfo.InvariantCulture)+" inert compute bytes; SHA256 "+result+". Original-client base64 follows; no file saved, product principal/grant, model inference, content publication, workflow effect or production qualification.";}
        public void Dispose() {completed=false;if(bytes!=null) {Array.Clear(bytes,0,bytes.Length);bytes=null;}}
    }

    internal sealed class HostedComputeInputs : IDisposable
    {
        internal readonly string Release;internal readonly GuestComputeRequest Request;internal readonly HostedComputeReceiver Receiver;
        private readonly InstalledInputLease input;private readonly ConsoleCancelEventHandler cancel;private int cancelled;
        internal HostedComputeInputs(string[] arguments)
        {
            if(arguments==null || arguments.Length!=4) throw new InvalidDataException("compute ACTIVE_RELEASE_SHA256 OPERATION PAYLOAD_FILE");
            Wire.Bytes(arguments[1],32,true);Release=arguments[1];
            try {
                input=InstalledInputLease.Acquire(arguments[3]);
                if(input.Length<1 || input.Length>HostedComputeContract.MaximumPayloadBytes) throw new SecurityException("Original compute input must be one exact nonempty file of at most4096 bytes.");
                byte[] payload=new byte[(int)input.Length];
                try {
                    Stream stream=input.Rewind();int at=0;while(at<payload.Length) {input.Check();int read=stream.Read(payload,at,payload.Length-at);if(read==0) throw new EndOfStreamException("Original held compute input truncated.");at+=read;input.Check();}
                    if(stream.ReadByte()!=-1) throw new SecurityException("Original held compute input grew.");input.Check();
                    Request=new GuestComputeRequest(arguments[2],new UTF8Encoding(false,true).GetString(payload));HostedComputeContract.Decode(Request.Bytes);
                }
                finally {Array.Clear(payload,0,payload.Length);}
                Receiver=new HostedComputeReceiver(Request.RequestSha256);cancel=delegate(object sender,ConsoleCancelEventArgs args) {Interlocked.Exchange(ref cancelled,1);args.Cancel=true;};Console.CancelKeyPress+=cancel;
            }catch {Dispose();throw;}
        }
        internal void Check() {if(Interlocked.CompareExchange(ref cancelled,0,0)!=0) throw new OperationCanceledException("Compute cancelled; partial delivery is possible and any uncertain controller generation remains fenced until exact explicit recovery.");input.Check();}
        internal void Reviewed(byte[] exact,string hash) {Check();HostedComputeContract.ValidateReview(exact,Request,Release);Receiver.Reviewed(hash);}
        internal void Print(Action check)
        {
            Check();Console.WriteLine(Receiver.Summary());string value=Receiver.ResultBase64();
            for(int at=0;at<value.Length;at+=4096) {check();Console.Write(value.Substring(at,Math.Min(4096,value.Length-at)));check();}Console.WriteLine();
        }
        public void Dispose() {if(cancel!=null) Console.CancelKeyPress-=cancel;if(Receiver!=null) Receiver.Dispose();if(input!=null) input.Dispose();}
    }

    internal static partial class HostedCoordinator
    {
        private static ReleaseDescriptor ComputeRelease(NativeAuthority authority,DeploymentEvent active,out byte[] signature)
        {
            byte[] description=authority.State.Read(Ticket("r",active.ReleaseSha256),1,60000);signature=authority.State.Read(Ticket("s",active.ReleaseSha256),64,64);
            ReleaseDescriptor release=ReleaseDescriptor.Decode(description);
            if(Wire.Hash(description)!=active.ReleaseSha256 || release.Sequence!=active.ReleaseSequence) throw new SecurityException("Held retained publisher release differs from the authenticated active distribution.");return release;
        }
        private static void ComputeActive(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running)
        {
            string releaseHash=Wire.Hex(input.Fixed(32));GuestComputeRequest request=HostedComputeContract.Decode(input.Blob(HostedComputeContract.MaximumRequestBytes));input.End();
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());
                DeploymentHistory state=DeploymentHistory.Replay(history,original);
                if(state.Pending!=null || state.Active==null || state.Active.ReleaseSha256!=releaseHash) throw new SecurityException("Compute requires the one current genuinely activated distribution and no outstanding resource generation.");
                state.RequireFreshGeneration(request.RequestSha256);
                HostedComputeContract.RequireAdmissionCapacity(history);authority.State.RequireReadableTail();
                AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,state.Active,out signature);release.Verify(authority.Trust.ForRelease(),signature);
                HostedReleaseLease utc=new HostedReleaseLease(pipe,authority,release,signature,original);utc.Check();
                HostedProtectionLease protection=new HostedProtectionLease(authority.State,actor,original);
                DeploymentEvent admission=new DeploymentEvent(3,releaseHash,release.Sequence,request.RequestSha256,HostedHostResources.BootCreation(),state.Active.PackageLeaf,0,0,0,new string('0',64));
                byte[] review=Review(pipe,"compute",HostedComputeContract.ReviewBytes(admission,request,history.Head),
                    "One30-second original first-Admin INERT computation; operation "+request.Operation+"\nExact request SHA256: "+request.RequestSha256+"\nExact payload SHA256: "+request.PayloadSha256+
                    "\nCurrent publisher-authenticated active release: "+releaseHash+"\nOwned distribution: "+HostedGuestRunner.Distribution(authority.Identity,admission)+
                    "\nInput <=4096 UTF8 bytes /8192 canonical encoded bytes; output <=16MiB; request, subprocess, independent UTC, cancellation and delivery share the original30-second deadline. No Linux/product principal, finite grant, model inference, content publication or workflow effect. Interrupted execution is never replayed; exact original exit and guest drainage must be reviewed before releasing its resource generation.",utc.CheckObserved);
                HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());
                Action writing=delegate {original();authority.State.Check();protection.Check();utc.CheckObserved();HostedHostResources.Check(256UL*1024*1024);};
                Action live=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);live();};
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);live();
                    protection.CheckFresh();append(JournalKind.ComputePrepared,admission.Encode());DeploymentEvent started=null;
                    byte[] result=HostedGuestRunner.Compute(execution,actor,admission,request,delegate(OwnedWindowsProcess controller) {
                        live();protection.CheckFresh();if(started!=null) throw new SecurityException("Compute cannot dispatch a second controller or retry its exact request.");
                        started=admission.WithController(controller.Id,controller.Creation,0,request.RequestSha256);append(JournalKind.ControllerStarted,started.Encode());protection.CheckFresh();
                    },live);
                    try {
                        live();directory.Check();if(started==null || !OwnedWindowsProcess.OriginalExited(started.Controller,started.ControllerCreation)) throw new SecurityException("Exact original compute controller exit is unobserved.");
                        string digest=HostedComputeContract.Digest(result);append(JournalKind.ControllerCompleted,started.WithController(started.Controller,started.ControllerCreation,1,digest).Encode());
                        append(JournalKind.ComputeObserved,admission.WithController(0,0,1,digest).Encode());
                        JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory final=DeploymentHistory.Replay(completed,live);
                        if(final.Pending!=null || final.Active==null || final.Active.ReleaseSha256!=releaseHash) throw new SecurityException("Completed compute did not release only its own resource generation while retaining the exact active release.");
                        HostedComputeDelivery delivery=new HostedComputeDelivery(Wire.Hash(review),request.RequestSha256,result);
                        Action delivering=delegate {live();directory.Check();NoUncertainFileAuthority(authority);if(authority.Nv.ReadHead()!=completed.Head) throw new SecurityException("Protected authority changed during original-client compute delivery.");};
                        try {
                            while(!delivery.Complete) {delivering();byte[] chunk=delivery.Next();try {Reply(pipe,"compute-chunk",chunk,delivering);}finally {Array.Clear(chunk,0,chunk.Length);}byte[] ack=HostedPipe.Read(pipe,delivering,Standard);try {delivering();delivery.Acknowledge(ack);}finally {Array.Clear(ack,0,ack.Length);}}
                            Reply(pipe,"compute-completed",delivery.Receipt(completed.Head),delivering);
                        }finally {delivery.Clear();}
                    }finally {Array.Clear(result,0,result.Length);}
                }
            }
        }
        private static void RecoverCompute(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running)
        {
            string releaseHash=Wire.Hex(input.Fixed(32)),generation=Wire.Hex(input.Fixed(32));input.End();Wire.Bytes(releaseHash,32,true);Wire.Bytes(generation,32,true);
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,RuntimeAccess.Standard,true)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(history,original);DeploymentEvent admission=state.Pending;
                if(admission==null || admission.Purpose!=3 || admission.ReleaseSha256!=releaseHash || admission.Generation!=generation) throw new SecurityException("Compute recovery requires the exact genuinely outstanding request generation and active release, not an automatic retry.");
                string drainRequest=state.DrainRequestSha256();
                byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,admission,out signature);AuthorityIdentity verifier=authority.Trust.ForCleanup(generation);release.Verify(verifier,signature);
                HostedReleaseLease utc=HostedReleaseLease.ForAbandonment(pipe,authority,release,signature,original,verifier);utc.Check();
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-compute-recovery-v1")) {exact.Blob(admission.Encode(),4096);exact.Fixed(Wire.Bytes(history.Head,32,true),32);
                    Review(pipe,"compute-recover",exact.Bytes(),"Close only interrupted inert request "+generation+"\nCurrent release: "+releaseHash+"\nExact request revocation: "+drainRequest+"\nRequires exact original controller exit, durable append-only guest request revocation, no queued unit job and fresh confined guest drain. The marker is a negative execution barrier, not TPM/grant authority, and is never automatically removed. No request replay, adoption of partial output, successful result claim, distribution deletion, name-based process kill or product authority.",utc.CheckObserved);}
                HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());
                Action writing=delegate {original();authority.State.Check();utc.CheckObserved();};
                Action live=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);live();};
                AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);
                    if(state.Worker!=null && !OwnedWindowsProcess.OriginalExited(state.Worker.Controller,state.Worker.ControllerCreation)) throw new SecurityException("Original compute controller is still present; its resource generation remains held.");
                    HostedGuestRunner.Drain(execution,actor,admission,drainRequest,live);directory.Check();live();
                    string proof=HostedComputeContract.Digest(Encoding.ASCII.GetBytes("luma-compute-original-exit-and-confined-drain-no-replay-v1\n"+generation+"\n"+HostedHostResources.BootCreation().ToString(CultureInfo.InvariantCulture)));
                    if(state.Worker!=null) append(JournalKind.ControllerCompleted,state.Worker.WithController(state.Worker.Controller,state.Worker.ControllerCreation,2,proof).Encode());
                    append(JournalKind.Cancelled,admission.WithController(0,0,2,proof).Encode());
                    JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());if(DeploymentHistory.Replay(completed,live).Pending!=null) throw new SecurityException("Exact compute recovery did not reconstruct its terminal cancellation.");
                    using(Wire.Writer receipt=new Wire.Writer("luma-windows-hosted-compute-recovered-v1")) {receipt.Fixed(Wire.Bytes(releaseHash,32,true),32);receipt.Fixed(Wire.Bytes(generation,32,true),32);receipt.Fixed(Wire.Bytes(completed.Head,32,true),32);receipt.U8(0);receipt.U8(0);Reply(pipe,"compute-recovered",receipt.Bytes(),live);}
                }
            }
        }
    }
}
