using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Luma.Windows.Hosted
{
    internal static class HostedStatusShape
    {
        internal static void Require(byte purpose,string pending,uint controller,ulong creation) {
            if(pending==null || purpose>5 || (pending.Length==0)!=(purpose==0) || (controller==0)!=(creation==0))
                throw new SecurityException("Status resource generation shape differs.");
            if(pending.Length!=0) Wire.Bytes(pending,32,true);
        }
    }

    // Original-client ephemeral DATA only. No server accepts this object or a
    // prior Read receipt as authority for inference or subsequent filesystem use.
    internal sealed class HostedIngestionSnapshot : IDisposable
    {
        internal readonly EnrolledReadIntent Intent;
        private byte[] bytes;private bool consumed,disposed;
        private HostedIngestionSnapshot(EnrolledReadIntent intent,byte[] content) {Intent=intent;bytes=content;}
        internal static HostedIngestionSnapshot FromCompleted(HostedReadInputs read) {
            if(read==null) throw new ArgumentNullException("read");
            return new HostedIngestionSnapshot(read.Intent,read.TakeCompletedForInference());
        }
        internal GuestInferenceRequest CreateRequest(string runtime,string profile,uint maximum) {
            if(disposed || consumed || bytes==null) throw new SecurityException("Ingestion snapshot was cleared or already forwarded; a new actual Read ceremony is required.");
            string prompt=new UTF8Encoding(false,true).GetString(bytes);
            GuestInferenceRequest request=new GuestInferenceRequest(runtime,profile,prompt,maximum);
            if(request.PromptBytes!=Intent.Bytes || request.PromptSha256!=Intent.Sha256) throw new SecurityException("Inference changed the complete source snapshot; no hidden system instructions, lossy conversion, truncation or current-file substitution is allowed.");
            consumed=true;Array.Clear(bytes,0,bytes.Length);bytes=null;return request;
        }
        public void Dispose() {disposed=true;if(bytes!=null) {Array.Clear(bytes,0,bytes.Length);bytes=null;}}
    }

    internal sealed class HostedIngestionInputs : IDisposable
    {
        internal readonly string Release,Runtime,Profile;internal readonly uint Maximum;internal readonly HostedReadInputs Read;
        private readonly string owner;private readonly ConsoleCancelEventHandler cancel;private int cancelled;
        internal HostedIngestionInputs(string[] arguments,bool interactive) {
            if(arguments==null || arguments.Length!=10 || arguments[0]!="infer-enrolled-file")
                throw new InvalidDataException("infer-enrolled-file RELEASE_SHA256 INSTALLATION ROOT RELATIVE_PATH EXACT_BYTES SHA256 RUNTIME_MANIFEST_SHA256 PROFILE_SHA256 MAX_TOKENS");
            Wire.Bytes(arguments[1],32,true);Wire.Bytes(arguments[7],32,true);Wire.Bytes(arguments[8],32,true);
            uint maximum;if(!UInt32.TryParse(arguments[9],NumberStyles.None,CultureInfo.InvariantCulture,out maximum) || maximum<1 || maximum>512 || maximum.ToString(CultureInfo.InvariantCulture)!=arguments[9])
                throw new SecurityException("Ingestion requires an exact canonical finite output limit of one to512 tokens.");
            Release=arguments[1];Runtime=arguments[7];Profile=arguments[8];Maximum=maximum;
            try {
                Read=new HostedReadInputs(new string[]{"read-enrolled-file",arguments[2],arguments[3],arguments[4],arguments[5],arguments[6]},false);
                if(Read.Intent.Bytes>GuestInferenceRequest.MaximumPrompt) throw new SecurityException("Ingestion selects the complete file of at most4096 bytes; never a partial file or silent truncation.");owner=Read.Intent.Owner;
                if(interactive) {cancel=delegate(object sender,ConsoleCancelEventArgs eventArgs) {Interlocked.Exchange(ref cancelled,1);eventArgs.Cancel=true;};Console.CancelKeyPress+=cancel;}
            }catch {Dispose();throw;}
        }
        internal void Check() {
            if(Interlocked.CompareExchange(ref cancelled,0,0)!=0) throw new OperationCanceledException("Ingestion cancelled; a read may already have delivered bytes, and any submitted inference remains subject to its own exact recovery.");
            Read.Check();using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) if(!identity.IsAuthenticated || identity.User==null || identity.User.Value!=owner)
                throw new SecurityException("Original ingestion client Windows owner changed between its independent purposes.");
        }
        public void Dispose() {if(cancel!=null) Console.CancelKeyPress-=cancel;if(Read!=null) Read.Dispose();}
    }

    internal static partial class HostedAuthorityProgram
    {
        private static string IngestionLine(Action check,Stopwatch age,TimeSpan maximum) {
            // A timed-out console read is never reused by another ceremony.
            // This fixed CLI exits on failure; no second console reader starts.
            return GuestComputeFrames.Await(Task.Factory.StartNew(delegate {
                StringBuilder value=new StringBuilder();
                for(int index=0;index<256;index++) {int next=Console.Read();if(next<0) return null;if(next=='\n') return value.ToString().TrimEnd('\r');value.Append((char)next);}
                throw new SecurityException("Exact ingestion confirmation exceeded its fixed character bound.");
            }),check,age,maximum);
        }
        private static void IngestionHello(NamedPipeClientStream pipe,Action check) {
            using(Wire.Writer hello=new Wire.Writer("luma-windows-hosted-hello-v1")) {hello.U32(1);HostedPipe.Write(pipe,hello.Bytes(),check,TimeSpan.FromSeconds(30));}
        }
        private static void IngestionConfirm(NamedPipeClientStream pipe,byte[] payload,string command,Action<byte[],string> reviewed,Action check,Stopwatch age,TimeSpan maximum) {
            string hash=Wire.Hash(payload);using(Wire.Reader reader=new Wire.Reader(payload,"luma-windows-hosted-reviewed-action-v1")) {
                if(reader.Text(32)!=command) throw new SecurityException("Ingestion review crossed its independent read/inference purpose.");reader.Fixed(32);byte[] exact=reader.Blob(8192);
                try {string detail=reader.Text(16000);reader.End();reviewed(exact,hash);check();Console.WriteLine(detail);}finally {Array.Clear(exact,0,exact.Length);}
            }
            Console.WriteLine("Confirm ONLY this independent exact action: CONFIRM "+hash);
            if(IngestionLine(check,age,maximum)!="CONFIRM "+hash) throw new SecurityException("Exact independent ingestion action was not confirmed.");
            check();using(Wire.Writer confirmation=new Wire.Writer("luma-windows-hosted-confirm-v1")) {confirmation.Fixed(Wire.Bytes(hash,32,true),32);HostedPipe.Write(pipe,confirmation.Bytes(),check,TimeSpan.FromSeconds(30));}
        }
        private static HostedIngestionSnapshot IngestionRead(HostedIngestionInputs inputs) {
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",HostedPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)) {
                Stopwatch age=Stopwatch.StartNew();Action check=delegate {inputs.Check();HostedPipe.CheckServer(pipe);if(age.Elapsed>=TimeSpan.FromSeconds(30)) throw new SecurityException("Original Read purpose expired; no complete ingestion snapshot is inferred.");};
                inputs.Check();pipe.Connect(3000);check();IngestionHello(pipe,check);
                using(Wire.Writer request=new Wire.Writer("luma-windows-hosted-request-v1")) {request.Text("read-enrolled-file",32);request.Blob(inputs.Read.Intent.Encode(),2048);HostedPipe.Write(pipe,request.Bytes(),check,TimeSpan.FromSeconds(30));}
                while(true) {
                    byte[] response=HostedPipe.Read(pipe,check,TimeSpan.FromSeconds(30));
                    try {using(Wire.Reader frame=new Wire.Reader(response,"luma-windows-hosted-response-v1")) {
                        string kind=frame.Text(32);byte[] payload=frame.Blob(60000);frame.End();
                        try {
                            if(kind=="refused") throw new SecurityException("Actual Read service refused; no complete ingestion snapshot or inference authority is inferred.");
                            if(kind=="utc-challenge") {HostedTimeEndpoint.Deliver(pipe,payload,Wire.Hash(inputs.Read.Intent.Encode()),check);continue;}
                            if(kind=="review") {IngestionConfirm(pipe,payload,"read-enrolled-file",inputs.Read.Reviewed,check,age,TimeSpan.FromSeconds(30));continue;}
                            if(kind=="read-chunk") {byte[] ack=inputs.Read.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                            if(kind=="read-completed") {inputs.Read.Completed(payload);check();return HostedIngestionSnapshot.FromCompleted(inputs.Read);}
                            throw new SecurityException("Unexpected frame cannot cross into the original Read ceremony.");
                        }finally {Array.Clear(payload,0,payload.Length);}
                    }}finally {Array.Clear(response,0,response.Length);}
                }
            }
        }
        private static int IngestionInfer(HostedIngestionInputs inputs,GuestInferenceRequest request) {
            using(HostedInferenceReceiver receiver=new HostedInferenceReceiver(request.RequestSha256))
            using(NamedPipeClientStream pipe=new NamedPipeClientStream(".",HostedPipe.Name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)) {
                Stopwatch age=Stopwatch.StartNew();Action check=delegate {inputs.Check();HostedPipe.CheckServer(pipe);HostedInferenceContract.RequireElapsed(age.Elapsed);};
                inputs.Check();pipe.Connect(3000);check();IngestionHello(pipe,check);
                byte[] bytes=request.Bytes;try {using(Wire.Writer command=new Wire.Writer("luma-windows-hosted-request-v1")) {command.Text("infer",32);command.Fixed(Wire.Bytes(inputs.Release,32,true),32);command.Blob(bytes,GuestInferenceRequest.MaximumEncoded);HostedPipe.Write(pipe,command.Bytes(),check,TimeSpan.FromSeconds(30));}}
                finally {Array.Clear(bytes,0,bytes.Length);}
                while(true) {
                    byte[] response=HostedPipe.Read(pipe,check,TimeSpan.FromSeconds(HostedInferenceContract.PurposeSeconds));
                    try {using(Wire.Reader frame=new Wire.Reader(response,"luma-windows-hosted-response-v1")) {
                        string kind=frame.Text(32);byte[] payload=frame.Blob(60000);frame.End();
                        try {
                            if(kind=="refused") throw new SecurityException("Actual inference service refused; inspect its exact resource generation if submission began. No replay or release is inferred.");
                            if(kind=="utc-challenge") {HostedTimeEndpoint.Deliver(pipe,payload,inputs.Release,check);continue;}
                            if(kind=="review") {IngestionConfirm(pipe,payload,"infer",delegate(byte[] exact,string hash) {HostedInferenceContract.ValidateReview(exact,request,inputs.Release);receiver.Reviewed(hash);},check,age,TimeSpan.FromSeconds(HostedInferenceContract.PurposeSeconds));continue;}
                            if(kind=="inference-chunk") {byte[] ack=receiver.Part(payload);try {HostedPipe.Write(pipe,ack,check,TimeSpan.FromSeconds(30));}finally {Array.Clear(ack,0,ack.Length);}continue;}
                            if(kind=="inference-completed") {
                                receiver.Finish(payload);check();Console.WriteLine(receiver.Summary());string result=receiver.ResultBase64();
                                for(int at=0;at<result.Length;at+=4096) {check();Console.Write(result.Substring(at,Math.Min(4096,result.Length-at)));check();}Console.WriteLine();return 0;
                            }
                            throw new SecurityException("Unexpected frame cannot cross into the fresh inference ceremony.");
                        }finally {Array.Clear(payload,0,payload.Length);}
                    }}finally {Array.Clear(response,0,response.Length);}
                }
            }
        }
        private static int IngestClient(string[] arguments) {
            if(Console.IsInputRedirected || Console.IsOutputRedirected) throw new SecurityException("Original interactive owner must independently confirm Read and inference; no redirected ingestion.");
            using(HostedIngestionInputs inputs=new HostedIngestionInputs(arguments,true)) {
                Console.WriteLine("First ceremony: exact scoped host-file READ only, at most4096 bytes and30 seconds. The enrolled first Admin, actual local NTFS owner/ACL/object, protected UTC and current NV are checked by the existing service. No model runs in this ceremony.");
                using(HostedIngestionSnapshot snapshot=IngestionRead(inputs)) {
                    Stopwatch handoff=Stopwatch.StartNew();Action check=delegate {inputs.Check();if(handoff.Elapsed>=TimeSpan.FromSeconds(30)) throw new SecurityException("Explicit snapshot-forward choice expired; no inference was requested.");};
                    check();Console.WriteLine("READ COMPLETED and its pipe CLOSED. Already-delivered snapshot bytes/SHA256: "+snapshot.Intent.Bytes+" / "+snapshot.Intent.Sha256+
                        "\nThis is NOT current file access, a portable grant, proof of a current version, a citation or authority. The source may change or be revoked now; it is not re-read.\nSecond ceremony uses a NEW nonce/pipe, fresh actual first-Admin authentication, current signed model/runtime/release, protected UTC, resource admission and an independent five-minute inference review.\nNo hidden system instructions: the entire exact UTF8 source is user text within fixed, visible ChatML user/assistant framing with an empty thinking prefill. Model text remains untrusted; no publication, OS effect, file save or ordinary-user/Linux principal is created.\nType INFER "+snapshot.Intent.Sha256+" to request that separate review, or anything else to cancel:");
                    if(IngestionLine(check,handoff,TimeSpan.FromSeconds(30))!="INFER "+snapshot.Intent.Sha256) {Console.WriteLine("Stopped after the completed Read. No inference was requested; already-delivered bytes cannot be recalled.");return 0;}
                    check();GuestInferenceRequest request=snapshot.CreateRequest(inputs.Runtime,inputs.Profile,inputs.Maximum);return IngestionInfer(inputs,request);
                }
            }
        }
    }
}
