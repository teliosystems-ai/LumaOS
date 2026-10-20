using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Luma.Windows.Hosted
{
    // A separate, nonrenewable original-Admin purpose. A model response is data,
    // not a native product principal, finite grant, effect or publication.
    public sealed class GuestInferenceRequest
    {
        public const string Profile="luma-windows-hosted-inference-v1";
        public const string ModelSha256="7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5";
        public const string ProfilePath="usr/share/luma-os/hosted-inference.json";
        public const int MaximumEncoded=32768,MaximumPrompt=4096,MaximumResult=1048576;
        public const ulong MemoryBytes=4831838208;
        public string Nonce {get;private set;}
        public string RuntimeManifestSha256 {get;private set;}
        public string ProfileSha256 {get;private set;}
        public string PromptSha256 {get;private set;}
        public int PromptBytes {get;private set;}
        public uint MaximumTokens {get;private set;}
        private readonly byte[] encoded;
        public byte[] Bytes {get{return (byte[])encoded.Clone();}}
        public string RequestSha256 {get{return HostedComputeContract.Digest(encoded);}}
        public GuestInferenceRequest(string runtime,string profile,string prompt,uint maximumTokens)
            :this(runtime,profile,prompt,maximumTokens,Wire.Hex(Wire.Random(32))) {}
        private GuestInferenceRequest(string runtime,string profile,string prompt,uint maximumTokens,string nonce)
        {
            Wire.Bytes(runtime,32,true);Wire.Bytes(profile,32,true);Wire.Bytes(nonce,32,true);
            if(prompt==null || prompt.IndexOf('\0')>=0 || maximumTokens<1 || maximumTokens>512) throw new SecurityException("Inference prompt or finite output-token budget differs.");
            byte[] bytes;try {bytes=new UTF8Encoding(false,true).GetBytes(prompt);}catch(EncoderFallbackException error) {throw new SecurityException("Inference prompt is not valid scalar UTF8.",error);}
            try {
                if(bytes.Length<1 || bytes.Length>MaximumPrompt) throw new SecurityException("Inference prompt must be exact nonempty UTF8 of at most4096 bytes.");
                Nonce=nonce;RuntimeManifestSha256=runtime;ProfileSha256=profile;PromptSha256=HostedComputeContract.Digest(bytes);PromptBytes=bytes.Length;MaximumTokens=maximumTokens;
                encoded=new UTF8Encoding(false,true).GetBytes("{\"schema_version\":1,\"profile\":"+GuestComputeRequest.Quote(Profile)+",\"nonce\":"+GuestComputeRequest.Quote(nonce)+
                    ",\"model_sha256\":"+GuestComputeRequest.Quote(ModelSha256)+",\"runtime_manifest_sha256\":"+GuestComputeRequest.Quote(runtime)+",\"profile_sha256\":"+GuestComputeRequest.Quote(profile)+
                    ",\"prompt\":"+GuestComputeRequest.Quote(prompt)+",\"prompt_sha256\":"+GuestComputeRequest.Quote(PromptSha256)+",\"context_tokens\":2048,\"max_tokens\":"+maximumTokens.ToString(CultureInfo.InvariantCulture)+"}");
                if(encoded.Length>MaximumEncoded) throw new SecurityException("Canonical inference request exceeds its separate finite transport budget.");
            }finally {Array.Clear(bytes,0,bytes.Length);}
        }
        public static GuestInferenceRequest Decode(byte[] bytes)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(Wire.Copy(bytes,1,MaximumEncoded),MaximumEncoded);
            string[] names={"schema_version","profile","nonce","model_sha256","runtime_manifest_sha256","profile_sha256","prompt","prompt_sha256","context_tokens","max_tokens"};
            if(fields.Count!=names.Length) throw new SecurityException("Inference request has missing or unknown fields.");
            foreach(string name in names) if(!fields.ContainsKey(name)) throw new SecurityException("Inference request omitted a required field.");
            foreach(string name in new string[]{"profile","nonce","model_sha256","runtime_manifest_sha256","profile_sha256","prompt","prompt_sha256"})
                if(!(fields[name] is string)) throw new SecurityException("Inference request string type differs.");
            foreach(string name in new string[]{"schema_version","context_tokens","max_tokens"}) if(!(fields[name] is ulong)) throw new SecurityException("Inference request integer type differs.");
            if((ulong)fields["schema_version"]!=1 || (string)fields["profile"]!=Profile || (string)fields["model_sha256"]!=ModelSha256 ||
                (ulong)fields["context_tokens"]!=2048 || (ulong)fields["max_tokens"]<1 || (ulong)fields["max_tokens"]>512) throw new SecurityException("Inference schema, model, context or token selection differs.");
            GuestInferenceRequest request=new GuestInferenceRequest((string)fields["runtime_manifest_sha256"],(string)fields["profile_sha256"],(string)fields["prompt"],(uint)(ulong)fields["max_tokens"],(string)fields["nonce"]);
            if(request.PromptSha256!=(string)fields["prompt_sha256"] || !Wire.Equal(bytes,request.encoded)) throw new SecurityException("Inference request is noncanonical or its complete prompt hash differs.");return request;
        }
        public void RequireRelease(ReleaseDescriptor release)
        {
            if(release==null) throw new ArgumentNullException("release");if(release.Environment!="lab") throw new SecurityException("This separately approved compact inference profile is lab-only, not production-qualified custody.");bool found=false,runtime=false,model=false;
            foreach(Luma.Windows.RequiredFile file in release.RequiredFiles) if(file.Path==ProfilePath) {
                if(file.Sha256!=ProfileSha256 || file.Executable || file.Bytes<1 || file.Bytes>8192) throw new SecurityException("Inference profile is not the exact bounded publisher-authenticated data file.");found=true;
            }
            foreach(Luma.Windows.RequiredFile file in release.RequiredFiles) {
                if(file.Path=="usr/share/luma-os/hosted-inference-runtime.json") {if(file.Sha256!=RuntimeManifestSha256 || file.Executable || file.Bytes<1 || file.Bytes>16384) throw new SecurityException("Signed runtime manifest differs from original exact inference selection.");runtime=true;}
                if(file.Path=="usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf") {if(file.Sha256!=ModelSha256 || file.Executable || file.Bytes!=2497280256L) throw new SecurityException("Signed compact model differs from the fixed supported Qwen3-4B bytes.");model=true;}
            }
            if(!found || !runtime || !model) throw new SecurityException("The signed active release does not contain this exact inference profile, runtime and model; compute-only packages cannot acquire inference authority.");
        }
    }

    public sealed class GuestInferenceObservation
    {
        public string ResultSha256 {get;private set;}
        public int ResultBytes {get;private set;}
        public static GuestInferenceObservation Validate(GuestInferenceRequest request,byte[] metadata)
        {
            if(request==null) throw new ArgumentNullException("request");Dictionary<string,object> fields=ObservationJson.Parse(metadata);
            string[] expected={"schema_version","profile","nonce","request_sha256","model_sha256","runtime_manifest_sha256","profile_sha256","prompt_sha256","context_tokens","max_tokens","inference_executed","result_sha256","result_bytes",
                "uid","gid","supplementary_groups","cap_inheritable","cap_permitted","cap_effective","cap_bounding","cap_ambient","no_new_privileges","apparmor_profile","cgroup",
                "memory_max_bytes","memory_swap_max_bytes","tasks_max","cpu_quota_usec","cpu_period_usec","runtime_cpu_seconds","principal_authenticated","grants_admitted","authority_returned","committed","workflow_executed","production_qualified"};
            if(fields.Count!=expected.Length) throw new SecurityException("Inference observation has missing or unknown fields.");
            foreach(string name in expected) if(!fields.ContainsKey(name)) throw new SecurityException("Inference observation omitted a required field.");
            Func<string,string> text=delegate(string key) {if(!(fields[key] is string)) throw new SecurityException("Inference observation string type differs.");return (string)fields[key];};
            Func<string,ulong> number=delegate(string key) {if(!(fields[key] is ulong)) throw new SecurityException("Inference observation integer type differs.");return (ulong)fields[key];};
            Func<string,bool> boolean=delegate(string key) {if(!(fields[key] is bool)) throw new SecurityException("Inference observation boolean type differs.");return (bool)fields[key];};
            if(number("schema_version")!=1 || text("profile")!=GuestInferenceRequest.Profile || text("nonce")!=request.Nonce || text("request_sha256")!=request.RequestSha256 ||
                text("model_sha256")!=GuestInferenceRequest.ModelSha256 || text("runtime_manifest_sha256")!=request.RuntimeManifestSha256 || text("profile_sha256")!=request.ProfileSha256 ||
                text("prompt_sha256")!=request.PromptSha256 || number("context_tokens")!=2048 || number("max_tokens")!=request.MaximumTokens || !boolean("inference_executed") ||
                number("uid")!=65534 || number("gid")!=65534 || !boolean("no_new_privileges") || text("apparmor_profile")!="luma-hosted-inference" ||
                text("cgroup")!="0::/lumahosted.slice/luma-hosted-inference.service\n" || number("memory_max_bytes")!=GuestInferenceRequest.MemoryBytes || number("memory_swap_max_bytes")!=0 ||
                number("tasks_max")!=16 || number("cpu_quota_usec")!=200000 || number("cpu_period_usec")!=100000 || number("runtime_cpu_seconds")!=300)
                throw new SecurityException("Inference observation substituted the exact request, model, runtime or actual fixed confinement profile.");
            foreach(string name in new string[]{"cap_inheritable","cap_permitted","cap_effective","cap_bounding","cap_ambient"}) if(text(name)!="0000000000000000") throw new SecurityException("Inference retains capabilities.");
            foreach(string name in new string[]{"principal_authenticated","grants_admitted","authority_returned","committed","workflow_executed","production_qualified"}) if(boolean(name)) throw new SecurityException("Model output claims native product or publication authority.");
            List<ulong> groups=fields["supplementary_groups"] as List<ulong>;
            if(groups==null || groups.Count>1 || (groups.Count==1 && groups[0]!=65534)) throw new SecurityException("Inference supplementary group set differs.");
            ulong size=number("result_bytes");if(size<1 || size>GuestInferenceRequest.MaximumResult) throw new SecurityException("Inference result exceeds its finite bound.");
            string digest=text("result_sha256");Wire.Bytes(digest,32,true);return new GuestInferenceObservation {ResultBytes=(int)size,ResultSha256=digest};
        }
        public static void ValidateDrain(byte[] metadata)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(metadata);string[] names={"schema_version","profile","unit","cgroup_empty_or_absent","unit_inactive","authority_returned","job_completed"};
            if(fields.Count!=names.Length) throw new SecurityException("Inference drain has missing or unknown fields.");foreach(string name in names) if(!fields.ContainsKey(name)) throw new SecurityException("Inference drain omitted a required field.");
            if(!(fields["schema_version"] is ulong) || (ulong)fields["schema_version"]!=1 || !(fields["profile"] is string) || (string)fields["profile"]!=GuestInferenceRequest.Profile ||
                !(fields["unit"] is string) || (string)fields["unit"]!="luma-hosted-inference.service") throw new SecurityException("Inference drain substituted another resource profile.");
            foreach(string name in new string[]{"cgroup_empty_or_absent","unit_inactive"}) if(!(fields[name] is bool) || !(bool)fields[name]) throw new SecurityException("Inference resources are still active or unobserved.");
            foreach(string name in new string[]{"authority_returned","job_completed"}) if(!(fields[name] is bool) || (bool)fields[name]) throw new SecurityException("Read-only inference drain claims execution success or authority.");
        }
    }

    public static class GuestInferenceFrames
    {
        private static byte[] Exact(Stream input,int count,Action check,Stopwatch age)
        {
            byte[] bytes=new byte[count];int at=0;
            while(at<count) {check();int offset=at,length=Math.Min(32768,count-at);int read=GuestComputeFrames.Await(Task.Factory.StartNew(delegate {return input.Read(bytes,offset,length);}),check,age,TimeSpan.FromMinutes(5));
                if(read<1 || read>length) throw new EndOfStreamException("Inference response truncated.");at+=read;}return bytes;
        }
        private static void Send(Stream output,byte[] bytes,Action check,Stopwatch age)
        {
            for(int at=0;at<bytes.Length;at+=32768) {check();int offset=at,count=Math.Min(32768,bytes.Length-at);GuestComputeFrames.Await(Task.Factory.StartNew(delegate {output.Write(bytes,offset,count);output.Flush();return true;}),check,age,TimeSpan.FromMinutes(5));}
        }
        public static byte[] Exchange(GuestInferenceRequest request,Stream input,Stream output,Action check)
        {
            if(request==null || input==null || output==null || check==null) throw new ArgumentNullException("inference exchange");
            Stopwatch age=Stopwatch.StartNew();byte[] wire=request.Bytes;byte[] result=null;bool complete=false;
            try {
                Send(output,GuestComputeFrames.Length((uint)wire.Length),check,age);Send(output,wire,check,age);
                byte[] magic=Encoding.ASCII.GetBytes("LUMAWININFERv1!\n");if(!Wire.Equal(Exact(input,magic.Length,check,age),magic)) throw new SecurityException("Inference framing cannot borrow inert compute or another version.");
                byte[] length=Exact(input,4,check,age);uint size=((uint)length[0]<<24)|((uint)length[1]<<16)|((uint)length[2]<<8)|length[3];
                if(size<1 || size>8192) throw new SecurityException("Inference metadata exceeds its closed bound.");GuestInferenceObservation observed=GuestInferenceObservation.Validate(request,Exact(input,(int)size,check,age));
                result=new byte[observed.ResultBytes];int at=0;
                using(SHA256 hash=SHA256.Create()) {
                    while(at<result.Length) {byte[] part=Exact(input,Math.Min(32768,result.Length-at),check,age);try {Buffer.BlockCopy(part,0,result,at,part.Length);at+=part.Length;}finally {Array.Clear(part,0,part.Length);}
                        byte[] ack=new byte[40];ulong total=(ulong)at;for(int index=0;index<8;index++) ack[index]=unchecked((byte)(total>>(56-index*8)));
                        Buffer.BlockCopy(hash.ComputeHash(result,0,at),0,ack,8,32);try {check();Send(output,ack,check,age);}finally {Array.Clear(ack,0,ack.Length);}}
                    if(Wire.Hex(hash.ComputeHash(result))!=observed.ResultSha256) throw new SecurityException("Inference complete result hash differs.");
                }
                if(GuestComputeFrames.ExactEnd(input,check,age,TimeSpan.FromMinutes(5))!=-1) throw new SecurityException("Inference contains trailing unadvertised output.");
                new UTF8Encoding(false,true).GetCharCount(result);check();complete=true;return result;
            }finally {Array.Clear(wire,0,wire.Length);if(!complete && result!=null) Array.Clear(result,0,result.Length);}
        }
    }

    public sealed class HostedInferenceDelivery
    {
        private readonly string review,request,result;private readonly byte[] bytes;private int delivered,pending;private bool cleared;
        public int Delivered {get{return delivered;}}public bool Complete {get{return !cleared && delivered==bytes.Length && pending==0;}}
        public HostedInferenceDelivery(string review,string request,byte[] bytes)
        {
            Wire.Bytes(review,32,true);Wire.Bytes(request,32,true);
            if(bytes==null || bytes.Length<1 || bytes.Length>GuestInferenceRequest.MaximumResult) throw new SecurityException("Inference result exceeds the fixed complete delivery bound.");
            this.review=review;this.request=request;this.bytes=(byte[])bytes.Clone();result=HostedComputeContract.Digest(bytes);
        }
        public byte[] Next()
        {
            if(cleared || pending!=0 || Complete) throw new SecurityException("Inference delivery was cleared, has a pending chunk or is complete.");
            pending=Math.Min(32768,bytes.Length-delivered);
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-inference-chunk-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.Fixed(Wire.Bytes(result,32,true),32);
                writer.U32((uint)bytes.Length);writer.U32((uint)delivered);byte[] part=new byte[pending];Buffer.BlockCopy(bytes,delivered,part,0,pending);
                try {writer.Blob(part,32768);return writer.Bytes();}finally {Array.Clear(part,0,part.Length);}
            }
        }
        public void Acknowledge(byte[] frame)
        {
            if(cleared || pending==0) throw new SecurityException("No live exact inference chunk awaits acknowledgement.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-inference-ack-v1")) {
                int total=checked(delivered+pending);
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request || reader.U32()!=(uint)total) throw new SecurityException("Inference acknowledgement substituted review, request or cumulative offset.");
                byte[] digest;using(SHA256 hash=SHA256.Create()) digest=hash.ComputeHash(bytes,0,total);
                if(!Wire.Equal(reader.Fixed(32),digest)) throw new SecurityException("Inference acknowledgement omitted or changed delivered bytes.");reader.End();delivered=total;pending=0;
            }
        }
        public byte[] Receipt(string head)
        {
            if(!Complete) throw new SecurityException("Partial inference delivery has no complete receipt.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-inference-completed-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.Fixed(Wire.Bytes(result,32,true),32);
                writer.U32((uint)bytes.Length);writer.Fixed(Wire.Bytes(head,32,true),32);writer.U8(1);
                for(int index=0;index<6;index++) writer.U8(index==2?(byte)1:(byte)0);return writer.Bytes();
            }
        }
        public void Clear() {Array.Clear(bytes,0,bytes.Length);cleared=true;}
    }

    public sealed class HostedInferenceReceiver : IDisposable
    {
        private readonly string request;private string review,result;private byte[] bytes;private int received;private bool completed,disposed;
        public bool Complete {get{return completed;}}
        public HostedInferenceReceiver(string request) {Wire.Bytes(request,32,true);this.request=request;}
        public void Reviewed(string hash) {Wire.Bytes(hash,32,true);if(disposed || review!=null) throw new SecurityException("Inference cannot revive a disposed receiver or substitute a second interactive review.");review=hash;}
        public byte[] Part(byte[] frame)
        {
            if(disposed || review==null || completed) throw new SecurityException("Inference result crossed its original disposed, unreviewed or completed purpose.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-inference-chunk-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request) throw new SecurityException("Inference chunk substituted exact review/request.");
                string digest=Wire.Hex(reader.Fixed(32));Wire.Bytes(digest,32,true);uint length=reader.U32(),offset=reader.U32();byte[] part=reader.Blob(32768);reader.End();
                try {
                    if(length<1 || length>GuestInferenceRequest.MaximumResult || offset!=(uint)received || part.Length!=Math.Min(32768,(long)length-received)) throw new SecurityException("Inference chunk exceeds its complete finite budget or exact offset.");
                    if(bytes==null) {bytes=new byte[length];result=digest;}else if(length!=bytes.Length || result!=digest) throw new SecurityException("Inference result changed complete digest or length during delivery.");
                    if(part.Length==0) throw new SecurityException("Empty post-completion inference chunk refused.");Buffer.BlockCopy(part,0,bytes,received,part.Length);received+=part.Length;
                }finally {Array.Clear(part,0,part.Length);}
            }
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-inference-ack-v1")) {
                writer.Fixed(Wire.Bytes(review,32,true),32);writer.Fixed(Wire.Bytes(request,32,true),32);writer.U32((uint)received);
                using(SHA256 hash=SHA256.Create()) writer.Fixed(hash.ComputeHash(bytes,0,received),32);return writer.Bytes();
            }
        }
        public void Finish(byte[] frame)
        {
            if(disposed || completed || review==null || bytes==null || received!=bytes.Length) throw new SecurityException("Disposed, partial or replayed inference result has no complete receipt.");
            using(Wire.Reader reader=new Wire.Reader(frame,"luma-windows-hosted-inference-completed-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=review || Wire.Hex(reader.Fixed(32))!=request || Wire.Hex(reader.Fixed(32))!=result || reader.U32()!=received)
                    throw new SecurityException("Inference receipt substituted original reviewed request or complete result.");
                Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);if(reader.U8()!=1) throw new SecurityException("Inference receipt omits genuine completed delivery.");
                for(int index=0;index<6;index++) if(reader.U8()!=(index==2?1:0)) throw new SecurityException("Inference receipt substituted execution or unsupported principal, grant, workflow, publication or qualification authority.");reader.End();
            }
            if(HostedComputeContract.Digest(bytes)!=result) throw new SecurityException("Original-client complete inference result hash differs.");
            new UTF8Encoding(false,true).GetCharCount(bytes);completed=true;
        }
        public string ResultBase64() {if(!completed) throw new SecurityException("Uncompleted inference output cannot be exposed as a complete result.");return Convert.ToBase64String(bytes);}
        public string Summary() {if(!completed) throw new SecurityException("Inference result is incomplete.");return "Received "+received.ToString(CultureInfo.InvariantCulture)+" model response bytes; SHA256 "+result+". Original-client base64 follows; no file saved; actual model inference, but no product principal/grant, content publication, workflow effect or production qualification.";}
        public void Dispose() {disposed=true;completed=false;if(bytes!=null) {Array.Clear(bytes,0,bytes.Length);bytes=null;}}
    }


    internal sealed class HostedInferenceInputs : IDisposable
    {
        internal readonly string Release;internal readonly GuestInferenceRequest Request;internal readonly HostedInferenceReceiver Receiver;
        private readonly InstalledInputLease input;private readonly ConsoleCancelEventHandler cancel;private int cancelled;
        internal HostedInferenceInputs(string[] arguments)
        {
            if(arguments==null || arguments.Length!=3) throw new InvalidDataException("infer ACTIVE_RELEASE_SHA256 REQUEST_JSON_FILE");
            Wire.Bytes(arguments[1],32,true);Release=arguments[1];
            try {
                input=InstalledInputLease.Acquire(arguments[2]);if(input.Length<1 || input.Length>GuestInferenceRequest.MaximumEncoded) throw new SecurityException("Inference request exceeds its separate fixed bound.");
                byte[] bytes=new byte[(int)input.Length];try {Stream stream=input.Rewind();int at=0;while(at<bytes.Length) {input.Check();int count=stream.Read(bytes,at,bytes.Length-at);if(count<1) throw new EndOfStreamException("Held inference request truncated.");at+=count;input.Check();}
                    if(stream.ReadByte()!=-1) throw new SecurityException("Held inference request grew.");input.Check();Request=GuestInferenceRequest.Decode(bytes);
                }finally {Array.Clear(bytes,0,bytes.Length);}
                Receiver=new HostedInferenceReceiver(Request.RequestSha256);cancel=delegate(object sender,ConsoleCancelEventArgs args) {Interlocked.Exchange(ref cancelled,1);args.Cancel=true;};Console.CancelKeyPress+=cancel;
            }catch {Dispose();throw;}
        }
        internal void Check() {if(Interlocked.CompareExchange(ref cancelled,0,0)!=0) throw new OperationCanceledException("Inference cancelled; any uncertain generation remains held until explicit exact recovery.");input.Check();}
        internal void Reviewed(byte[] exact,string hash) {Check();HostedInferenceContract.ValidateReview(exact,Request,Release);Receiver.Reviewed(hash);}
        internal void Print(Action check) {Check();Console.WriteLine(Receiver.Summary());string value=Receiver.ResultBase64();for(int at=0;at<value.Length;at+=4096) {check();Console.Write(value.Substring(at,Math.Min(4096,value.Length-at)));check();}Console.WriteLine();}
        public void Dispose() {if(cancel!=null) Console.CancelKeyPress-=cancel;if(Receiver!=null) Receiver.Dispose();if(input!=null) input.Dispose();}
    }

    internal static partial class HostedCoordinator
    {
        private static Action InferenceLive(HostedActor actor,Action running,Stopwatch age)
        {return delegate {running();actor.Check();HostedInferenceContract.RequireElapsed(age.Elapsed);};}
        private static void InferenceActive(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running)
        {
            string releaseHash=Wire.Hex(input.Fixed(32));GuestInferenceRequest request=GuestInferenceRequest.Decode(input.Blob(GuestInferenceRequest.MaximumEncoded));input.End();
            Stopwatch age=Stopwatch.StartNew();Action original=InferenceLive(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(history,original);
                if(state.Pending!=null || state.Active==null || state.Active.ReleaseSha256!=releaseHash) throw new SecurityException("Inference requires the exact current activated distribution and no outstanding resource generation.");
                state.RequireFreshGeneration(request.RequestSha256);
                HostedComputeContract.RequireAdmissionCapacity(history);authority.State.RequireReadableTail();AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,state.Active,out signature);release.Verify(authority.Trust.ForRelease(),signature);request.RequireRelease(release);
                HostedReleaseLease utc=new HostedReleaseLease(pipe,authority,release,signature,original);utc.Check();
                HostedProtectionLease protection=new HostedProtectionLease(authority.State,actor,original);
                DeploymentEvent admission=new DeploymentEvent(4,releaseHash,release.Sequence,request.RequestSha256,HostedHostResources.BootCreation(),state.Active.PackageLeaf,0,0,0,new string('0',64));
                byte[] review=Review(pipe,"infer",HostedInferenceContract.ReviewBytes(admission,request,history.Head),
                    "One nonrenewable five-minute original first-Admin MODEL INFERENCE session; not the thirty-second inert compute purpose.\nExact request: "+request.RequestSha256+
                    "\nPrompt SHA256: "+request.PromptSha256+"\nQwen3-4B model SHA256: "+GuestInferenceRequest.ModelSha256+"\nRuntime manifest SHA256: "+request.RuntimeManifestSha256+
                    "\nPublisher-bound inference profile SHA256: "+request.ProfileSha256+"\nCurrent release: "+releaseHash+"\nOwned distribution: "+HostedGuestRunner.Distribution(execution,admission)+
                    "\nThe exact source is user text within fixed ChatML user/assistant framing with an empty thinking prefill, not a hidden system instruction. Prompt <=4096 UTF8 bytes, context2048, generated tokens <="+request.MaximumTokens+", result <=1MiB; CPU-only2threads/4.5GiB/no swap/16tasks. Windows and guest each require observed5.5GiB headroom before dispatch and retain a1GiB continuous low-water floor; these checks are observations, not atomic reservations or a no-impact guarantee for other workloads. Low headroom interrupts work and retains any uncertain generation for exact recovery. Review, protected UTC refresh, subprocess, drainage and delivery share the original five-minute deadline. No native product principal/grant, publication, workflow effect or production qualification. Interrupted work is never replayed; original exit and fresh confined drainage are mandatory before releasing its generation.",utc.CheckObserved);
                HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());
                Action writing=delegate {original();authority.State.Check();protection.Check();utc.CheckObserved();HostedInferenceContract.CheckHostHeadroom(false);};
                Action observed=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action live=delegate {original();authority.State.Check();utc.Check();observed();};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);observed();};
                Action starting=delegate {live();protection.CheckFresh();HostedInferenceContract.CheckHostHeadroom(true);};
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);starting();append(JournalKind.InferencePrepared,admission.Encode());DeploymentEvent started=null;
                    byte[] result=HostedGuestRunner.Infer(execution,actor,admission,request,delegate(OwnedWindowsProcess controller) {
                        starting();if(started!=null) throw new SecurityException("Inference cannot dispatch a second controller or replay the exact request.");started=admission.WithController(controller.Id,controller.Creation,0,request.RequestSha256);append(JournalKind.ControllerStarted,started.Encode());starting();
                    },live);
                    try {
                        live();directory.Check();if(started==null || !OwnedWindowsProcess.OriginalExited(started.Controller,started.ControllerCreation)) throw new SecurityException("Original inference controller exit is unobserved.");
                        string digest=HostedComputeContract.Digest(result);append(JournalKind.ControllerCompleted,started.WithController(started.Controller,started.ControllerCreation,1,digest).Encode());append(JournalKind.InferenceObserved,admission.WithController(0,0,1,digest).Encode());
                        JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory final=DeploymentHistory.Replay(completed,live);
                        if(final.Pending!=null || final.Active==null || final.Active.ReleaseSha256!=releaseHash) throw new SecurityException("Inference completion changed the active release or retained an outstanding generation.");
                        HostedInferenceDelivery delivery=new HostedInferenceDelivery(Wire.Hash(review),request.RequestSha256,result);
                        Action delivering=delegate {observed();directory.Check();if(authority.Nv.ReadHead()!=completed.Head) throw new SecurityException("Authority changed during original-client inference delivery.");};
                        try {
                            while(!delivery.Complete) {
                                // Refresh only before a chunk is sent. The original client
                                // expects an ACK dialogue until that chunk is acknowledged.
                                live();delivering();byte[] chunk=delivery.Next();try {Reply(pipe,"inference-chunk",chunk,delivering);}finally {Array.Clear(chunk,0,chunk.Length);}
                                byte[] ack=HostedPipe.Read(pipe,delivering,Standard);try {delivering();delivery.Acknowledge(ack);}finally {Array.Clear(ack,0,ack.Length);}
                            }
                            live();Reply(pipe,"inference-completed",delivery.Receipt(completed.Head),delivering);
                        }finally {delivery.Clear();}
                    }finally {Array.Clear(result,0,result.Length);}
                }
            }
        }
        private static void RecoverInference(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader input,Action running)
        {
            string releaseHash=Wire.Hex(input.Fixed(32)),generation=Wire.Hex(input.Fixed(32));input.End();Wire.Bytes(releaseHash,32,true);Wire.Bytes(generation,32,true);
            Stopwatch age=Stopwatch.StartNew();Action original=Live(actor,running,age);
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,RuntimeAccess.Standard,true)) {
                NoUncertainFileAuthority(authority);JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());DeploymentHistory state=DeploymentHistory.Replay(history,original);DeploymentEvent admission=state.Pending;
                if(admission==null || admission.Purpose!=4 || admission.ReleaseSha256!=releaseHash || admission.Generation!=generation) throw new SecurityException("Inference recovery requires the exact outstanding inference generation, never another purpose or automatic replay.");
                string drainRequest=state.DrainRequestSha256();
                byte[] signature;ReleaseDescriptor release=ComputeRelease(authority,admission,out signature);AuthorityIdentity verifier=authority.Trust.ForCleanup(generation);release.Verify(verifier,signature);
                HostedReleaseLease utc=HostedReleaseLease.ForAbandonment(pipe,authority,release,signature,original,verifier);utc.Check();
                using(Wire.Writer exact=new Wire.Writer("luma-windows-hosted-inference-recovery-v1")) {exact.Blob(admission.Encode(),4096);exact.Fixed(Wire.Bytes(history.Head,32,true),32);
                    Review(pipe,"infer-recover",exact.Bytes(),"Close only interrupted inference "+generation+"\nRelease: "+releaseHash+"\nExact request revocation: "+drainRequest+"\nRequires exact original controller exit, durable append-only guest request revocation, no queued unit job and fresh confined inference drain. The marker is only a negative execution barrier, not TPM/grant authority, and is never automatically removed. No model rerun, partial result adoption, distribution deletion, process-name kill or product authority.",utc.CheckObserved);}
                HostedComputeHead heldHead=new HostedComputeHead(authority.Identity,history,authority.Nv.ReadHead());Action writing=delegate {original();authority.State.Check();utc.CheckObserved();};
                Action live=delegate {writing();NoUncertainFileAuthority(authority);heldHead.Require(authority.Nv.ReadHead());};
                Action<JournalKind,byte[]> append=delegate(JournalKind kind,byte[] payload) {live();JournalEntry accepted=authority.Journal.Append(kind,actor.Sid,payload,writing);heldHead.Advance(accepted);live();};
                AuthorityIdentity execution=authority.Runtime.GuestExecutionIdentity;
                using(HostedGuestDirectory directory=HostedGuestDirectory.Open(execution,admission,false)) {
                    directory.Check();HostedWslConfiguration.RequireClosed(execution,actor,admission,live);
                    if(state.Worker!=null && !OwnedWindowsProcess.OriginalExited(state.Worker.Controller,state.Worker.ControllerCreation)) throw new SecurityException("Original inference controller remains present; its generation remains held.");
                    HostedGuestRunner.DrainInference(execution,actor,admission,drainRequest,live);directory.Check();live();
                    string proof=HostedComputeContract.Digest(Encoding.ASCII.GetBytes("luma-inference-original-exit-and-confined-drain-no-replay-v1\n"+generation+"\n"+HostedHostResources.BootCreation().ToString(CultureInfo.InvariantCulture)));
                    if(state.Worker!=null) append(JournalKind.ControllerCompleted,state.Worker.WithController(state.Worker.Controller,state.Worker.ControllerCreation,2,proof).Encode());append(JournalKind.Cancelled,admission.WithController(0,0,2,proof).Encode());
                    JournalHistory completed=authority.Journal.Read(live);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());if(DeploymentHistory.Replay(completed,live).Pending!=null) throw new SecurityException("Inference recovery did not reconstruct exact terminal cancellation.");
                    using(Wire.Writer receipt=new Wire.Writer("luma-windows-hosted-inference-recovered-v1")) {receipt.Fixed(Wire.Bytes(releaseHash,32,true),32);receipt.Fixed(Wire.Bytes(generation,32,true),32);receipt.Fixed(Wire.Bytes(completed.Head,32,true),32);receipt.U8(0);receipt.U8(0);Reply(pipe,"inference-recovered",receipt.Bytes(),live);}
                }
            }
        }
    }

    public static class HostedInferenceContract
    {
        public const int PurposeSeconds=300;
        public const ulong HostMemoryReserveBytes=1073741824UL;
        public const ulong HostMemoryStartBytes=GuestInferenceRequest.MemoryBytes+HostMemoryReserveBytes;
        // Observations do not reserve memory or guarantee coexistence with
        // arbitrary concurrent allocations. The guest also checks headroom.
        public static void RequireHostHeadroom(ulong available,bool starting)
        {if(available<(starting?HostMemoryStartBytes:HostMemoryReserveBytes)) throw new SecurityException("Inference lacks observed Windows memory headroom; no atomic resource reservation is inferred.");}
        internal static void CheckHostHeadroom(bool starting)
        {RequireHostHeadroom(HostedHostResources.AvailableMemory(),starting);}
        public static void RequireElapsed(TimeSpan elapsed)
        {if(elapsed<TimeSpan.Zero || elapsed>=TimeSpan.FromSeconds(PurposeSeconds)) throw new SecurityException("The exact five-minute inference purpose expired; no automatic renewal or compute fallback.");}
        public static byte[] ReviewBytes(DeploymentEvent admission,GuestInferenceRequest request,string head)
        {
            if(admission==null || request==null || admission.Purpose!=4 || admission.Generation!=request.RequestSha256 || admission.Controller!=0 || admission.ObservationKind!=0) throw new SecurityException("Inference review must bind its exact unexecuted request generation.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-inference-review-v1")) {
                writer.Blob(admission.Encode(),4096);writer.Fixed(Wire.Bytes(request.ProfileSha256,32,true),32);writer.Fixed(Wire.Bytes(request.RuntimeManifestSha256,32,true),32);
                writer.Fixed(Wire.Bytes(GuestInferenceRequest.ModelSha256,32,true),32);writer.Fixed(Wire.Bytes(request.PromptSha256,32,true),32);writer.U32(request.MaximumTokens);writer.Fixed(Wire.Bytes(head,32,true),32);return writer.Bytes();
            }
        }
        public static DeploymentEvent ValidateReview(byte[] exact,GuestInferenceRequest request,string release)
        {
            Wire.Bytes(release,32,true);using(Wire.Reader reader=new Wire.Reader(exact,"luma-windows-hosted-inference-review-v1")) {
                DeploymentEvent admission=DeploymentEvent.Decode(reader.Blob(4096));reader.Fixed(32);reader.Fixed(32);reader.Fixed(32);reader.Fixed(32);reader.U32();string head=Wire.Hex(reader.Fixed(32));reader.End();
                if(admission.ReleaseSha256!=release || !Wire.Equal(ReviewBytes(admission,request,head),exact)) throw new SecurityException("Inference review substituted original release, model, runtime, prompt or resource generation.");return admission;
            }
        }
    }
}
