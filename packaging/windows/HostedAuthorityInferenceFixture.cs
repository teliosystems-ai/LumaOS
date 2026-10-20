using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security;
using System.Text;
using Luma.Windows;
using Luma.Windows.Hosted;

// Software protocol fixtures only: no model execution, custody or deployment.
public static class LumaHostedInferenceFixture
{
    private static int assertions;
    private static string H(char value) {return new string(value,64);}
    private static byte[] B(string value) {return new UTF8Encoding(false,true).GetBytes(value);}
    public static byte[][] Requests() {
        List<byte[]> result=new List<byte[]>();
        foreach(string prompt in new string[]{"Exact compact model prompt","Escaped \"quote\" and \\ slash\r\n\t","\u00e9 \u6a21\u578b \ud83d\ude80","combining e\u0301",new string('x',4096),new string('\u0001',4096),new string('\u00e9',2048)}) {
            GuestInferenceRequest request=new GuestInferenceRequest(H('a'),H('b'),prompt,512);if(!Wire.Equal(GuestInferenceRequest.Decode(request.Bytes).Bytes,request.Bytes)) throw new Exception("Actual exported constructor request failed its closed codec.");result.Add(request.Bytes);
        }return result.ToArray();
    }
    private static void Require(bool condition) {if(!condition) throw new Exception("Inference software contract assertion failed.");assertions++;}
    private static void Refuse(Action action) {
        try {action();}catch(SecurityException) {assertions++;return;}catch(InvalidDataException) {assertions++;return;}catch(EndOfStreamException) {assertions++;return;}
        catch(EncoderFallbackException) {assertions++;return;}catch(DecoderFallbackException) {assertions++;return;}
        throw new Exception("Inference software contract accepted forbidden input.");
    }
    private static string Record(RequiredFile file) {return "{\"bytes\":"+file.Bytes.ToString(CultureInfo.InvariantCulture)+",\"executable\":"+(file.Executable?"true":"false")+",\"path\":\""+file.Path+"\",\"sha256\":\""+file.Sha256+"\"}";}
    private static string Profile(string sha) {return "{\"context_tokens\":2048,\"cpu_period_usec\":100000,\"cpu_quota_usec\":200000,\"environment\":\"lab\",\"maximum_output_tokens\":512,\"memory_max_bytes\":4831838208,\"memory_swap_max_bytes\":0,\"model_bytes\":2497280256,\"model_path\":\"usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf\",\"model_sha256\":\""+GuestInferenceRequest.ModelSha256+"\",\"profile\":\""+GuestInferenceRequest.Profile+"\",\"runtime\":\"llama.cpp-b11100-cpu-amd64-completion\",\"runtime_cpu_seconds\":300,\"runtime_manifest_sha256\":\""+sha+"\",\"schema_version\":1,\"tasks_max\":16,\"threads\":2}\n";}
    private static RequiredFile Data(string path,long size,string hash,bool executable) {return new RequiredFile {Path=path,Bytes=size,Sha256=hash,Executable=executable};}
    private static RequiredFile[] Descriptors(out string description,out string manifest) {
        List<RequiredFile> files=new List<RequiredFile>();
        foreach(string name in new string[]{"llama-completion","libllama-completion-impl.so","libggml-cpu-x64.so"}) files.Add(Data("usr/libexec/luma-os/hosted-llama/"+name,64,H('a'),name=="llama-completion"));
        foreach(string stem in new string[]{"libllama","libllama-common","libmtmd","libggml","libggml-base"}) foreach(string tail in new string[]{".so",".so.0",".so."+(stem=="libggml" || stem=="libggml-base"?"0.24.0":"0.4.1")}) files.Add(Data("usr/libexec/luma-os/hosted-llama/"+stem+tail,64,H('b'),false));
        files.Add(Data("usr/libexec/luma-os/luma-platform",64,H('c'),true));files.Add(Data("usr/lib/x86_64-linux-gnu/libstdc++.so.6",64,H('d'),false));
        files.Sort(delegate(RequiredFile a,RequiredFile b) {return String.CompareOrdinal(a.Path,b.Path);});List<string> records=new List<string>();foreach(RequiredFile file in files) records.Add(Record(file));
        manifest="{\"files\":["+String.Join(",",records.ToArray())+"],\"profile\":\""+GuestInferenceRequest.Profile+"\",\"schema_version\":1}\n";description=Profile(Wire.Hash(B(manifest)));
        files.Add(Data("usr/share/luma-os/models/qwen3-4b-q4-k-m.gguf",2497280256L,GuestInferenceRequest.ModelSha256,false));
        files.Add(Data("usr/share/luma-os/hosted-inference-runtime.json",B(manifest).Length,Wire.Hash(B(manifest)),false));files.Add(Data(GuestInferenceRequest.ProfilePath,B(description).Length,Wire.Hash(B(description)),false));return files.ToArray();
    }
    private static string Metadata(GuestInferenceRequest request,byte[] result) {
        return "{\"schema_version\":1,\"profile\":\""+GuestInferenceRequest.Profile+"\",\"nonce\":\""+request.Nonce+"\",\"request_sha256\":\""+request.RequestSha256+
            "\",\"model_sha256\":\""+GuestInferenceRequest.ModelSha256+"\",\"runtime_manifest_sha256\":\""+request.RuntimeManifestSha256+"\",\"profile_sha256\":\""+request.ProfileSha256+"\",\"prompt_sha256\":\""+request.PromptSha256+
            "\",\"context_tokens\":2048,\"max_tokens\":"+request.MaximumTokens.ToString(CultureInfo.InvariantCulture)+",\"inference_executed\":true,\"result_sha256\":\""+HostedComputeContract.Digest(result)+"\",\"result_bytes\":"+result.Length.ToString(CultureInfo.InvariantCulture)+
            ",\"uid\":65534,\"gid\":65534,\"supplementary_groups\":[],\"cap_inheritable\":\"0000000000000000\",\"cap_permitted\":\"0000000000000000\",\"cap_effective\":\"0000000000000000\",\"cap_bounding\":\"0000000000000000\",\"cap_ambient\":\"0000000000000000\",\"no_new_privileges\":true,\"apparmor_profile\":\"luma-hosted-inference\",\"cgroup\":\"0::/lumahosted.slice/luma-hosted-inference.service\\n\",\"memory_max_bytes\":4831838208,\"memory_swap_max_bytes\":0,\"tasks_max\":16,\"cpu_quota_usec\":200000,\"cpu_period_usec\":100000,\"runtime_cpu_seconds\":300,\"principal_authenticated\":false,\"grants_admitted\":false,\"authority_returned\":false,\"committed\":false,\"workflow_executed\":false,\"production_qualified\":false}";
    }
    private static byte[] Frames(GuestInferenceRequest request,string metadata,byte[] result,int mode) {
        using(MemoryStream input=new MemoryStream()) using(MemoryStream output=new MemoryStream()) {
            byte[] magic=B(mode==4?"LUMAWINCOMPv1!!\n":"LUMAWININFERv1!\n");input.Write(magic,0,magic.Length);byte[] description=B(metadata),length=GuestComputeFrames.Length((uint)description.Length);input.Write(length,0,4);input.Write(description,0,description.Length);
            byte[] bytes=(byte[])result.Clone();if(mode==2) bytes[0]^=1;input.Write(bytes,0,bytes.Length);if(mode==3) input.WriteByte(0);input.Position=0;int checks=0;
            byte[] actual=GuestInferenceFrames.Exchange(request,input,output,delegate {checks++;if(mode==1) throw new SecurityException("Actual inference frame cancellation.");});
            byte[] sent=output.ToArray();int chunks=(actual.Length+32767)/32768;Require(sent.Length==4+request.Bytes.Length+40*chunks && checks>chunks);
            int at=4+request.Bytes.Length;for(int chunk=0;chunk<chunks;chunk++) {int total=Math.Min(actual.Length,(chunk+1)*32768);ulong observed=0;for(int index=0;index<8;index++) observed=(observed<<8)|sent[at+index];Require(observed==(ulong)total);
                using(System.Security.Cryptography.SHA256 hash=System.Security.Cryptography.SHA256.Create()) {byte[] digest=hash.ComputeHash(actual,0,total);for(int index=0;index<32;index++) if(sent[at+8+index]!=digest[index]) throw new Exception("Inference actual cumulative ACK SHA256 differs.");}at+=40;}
            return actual;
        }
    }
    public static int Run(string workspace) {
        assertions=0;HostedInferenceContract.RequireElapsed(TimeSpan.Zero);HostedInferenceContract.RequireElapsed(TimeSpan.FromTicks(TimeSpan.FromMinutes(5).Ticks-1));Require(true);
        Require(HostedInferenceContract.HostMemoryReserveBytes==1024UL*1024*1024 && HostedInferenceContract.HostMemoryStartBytes==5905580032UL && HostedInferenceContract.HostMemoryStartBytes-HostedInferenceContract.HostMemoryReserveBytes==GuestInferenceRequest.MemoryBytes);
        foreach(ulong available in new ulong[]{HostedInferenceContract.HostMemoryStartBytes,UInt64.MaxValue}) {HostedInferenceContract.RequireHostHeadroom(available,true);Require(true);}
        foreach(ulong available in new ulong[]{HostedInferenceContract.HostMemoryReserveBytes,HostedInferenceContract.HostMemoryStartBytes,UInt64.MaxValue}) {HostedInferenceContract.RequireHostHeadroom(available,false);Require(true);}
        foreach(ulong available in new ulong[]{0,HostedInferenceContract.HostMemoryReserveBytes,HostedInferenceContract.HostMemoryStartBytes-1}) Refuse(delegate {HostedInferenceContract.RequireHostHeadroom(available,true);});
        foreach(ulong available in new ulong[]{0,HostedInferenceContract.HostMemoryReserveBytes-1}) Refuse(delegate {HostedInferenceContract.RequireHostHeadroom(available,false);});
        foreach(TimeSpan elapsed in new TimeSpan[]{TimeSpan.FromTicks(-1),TimeSpan.FromMinutes(5),TimeSpan.FromMinutes(6)}) Refuse(delegate {HostedInferenceContract.RequireElapsed(elapsed);});
        MethodInfo arguments=typeof(GuestInferenceRequest).Assembly.GetType("Luma.Windows.Hosted.HostedGuestRunner",true).GetMethod("Arguments",BindingFlags.NonPublic|BindingFlags.Static);
        string distribution="LumaHosted-"+H('a')+"-1-"+new string('b',32);
        Func<string,string,string,string[]> argv=delegate(string operation,string resource,string requestHash) {try {return (string[])arguments.Invoke(null,new object[]{distribution,operation,resource,requestHash});}catch(TargetInvocationException error) {throw error.InnerException;}};
        foreach(string operation in new string[]{"hosted-windows-compute-launch","hosted-windows-inference-launch"}) {
            string[] exact=argv(operation,H('c'),H('d'));Require(exact.Length==9 && exact[6]==operation && exact[7]==H('c') && exact[8]==H('d') && exact[5]=="/usr/libexec/luma-os/luma-platform");
            Refuse(delegate {argv(operation,H('c'),new string('0',64));});Refuse(delegate {argv(operation,null,H('d'));});
        }
        foreach(string operation in new string[]{"hosted-windows-compute-drain","hosted-windows-inference-drain"}) {
            string[] exact=argv(operation,null,H('d'));Require(exact.Length==8 && exact[6]==operation && exact[7]==H('d'));
            Refuse(delegate {argv(operation,H('c'),H('d'));});Refuse(delegate {argv(operation,null,new string('0',64));});
        }
        Refuse(delegate {argv("shell",H('c'),H('d'));});Refuse(delegate {argv("hosted-windows-inference-launch",H('c'),"-e injected");});
        string profile,manifest;RequiredFile[] files=Descriptors(out profile,out manifest);PackageInspector.ValidateInferenceDescriptors(profile,manifest,files);Require(true);
        foreach(string changed in new string[]{profile+" ",profile.Replace("\"threads\":2","\"threads\":3"),profile.Replace("\"environment\":\"lab\"","\"environment\":\"production\""),profile.Replace(GuestInferenceRequest.ModelSha256,H('f')),profile.Replace("\"runtime_cpu_seconds\":300","\"runtime_cpu_seconds\":30")}) Refuse(delegate {PackageInspector.ValidateInferenceDescriptors(changed,manifest,files);});
        foreach(string changed in new string[]{manifest+" ",manifest.Replace("\"schema_version\":1","\"schema_version\":true"),manifest.Replace("\"files\":[","\"files\":[{"),manifest.Replace("libggml-cpu-x64.so","libggml-rpc.so"),manifest.Replace("libstdc++.so.6","../../etc/shadow")}) Refuse(delegate {PackageInspector.ValidateInferenceDescriptors(Profile(Wire.Hash(B(changed))),changed,files);});
        foreach(RequiredFile target in files) {string old=target.Sha256;target.Sha256=H('f');Refuse(delegate {PackageInspector.ValidateInferenceDescriptors(profile,manifest,files);});target.Sha256=old;}
        foreach(string name in new string[]{"llama-server","llama-cli","libllama-cli-impl.so","libllama-server-impl.so"}) {
            List<RequiredFile> extra=new List<RequiredFile>(files);extra.Add(Data("usr/libexec/luma-os/hosted-llama/"+name,64,H('a'),true));Refuse(delegate {PackageInspector.ValidateInferenceDescriptors(profile,manifest,extra.ToArray());});
        }
        Refuse(delegate {PackageInspector.ValidateInferenceDescriptors(profile.Replace("llama.cpp-b11100-cpu-amd64-completion","llama.cpp-b11100-cpu-amd64-cli"),manifest,files);});
        int privateCount=0;foreach(RequiredFile file in files) if(file.Path.StartsWith("usr/libexec/luma-os/hosted-llama/",StringComparison.Ordinal)) privateCount++;Require(privateCount==18);
        GuestInferenceRequest request=new GuestInferenceRequest(Wire.Hash(B(manifest)),Wire.Hash(B(profile)),"Exact prompt",128);byte[] result=B(new string('x',70000));string metadata=Metadata(request,result);
        HostedInferenceReceiver disposed=new HostedInferenceReceiver(request.RequestSha256);disposed.Dispose();Refuse(delegate {disposed.Reviewed(H('a'));});
        HostedInferenceDelivery cleared=new HostedInferenceDelivery(H('a'),request.RequestSha256,result);cleared.Clear();Refuse(delegate {cleared.Next();});Refuse(delegate {cleared.Receipt(H('b'));});
        GuestInferenceObservation observed=GuestInferenceObservation.Validate(request,B(metadata));Require(observed.ResultBytes==result.Length && observed.ResultSha256==HostedComputeContract.Digest(result));
        foreach(string changed in new string[]{metadata.Replace(request.Nonce,H('f')),metadata.Replace(request.RuntimeManifestSha256,H('f')),metadata.Replace(request.ProfileSha256,H('f')),metadata.Replace(request.PromptSha256,H('f')),metadata.Replace(request.RequestSha256,H('f')),
            metadata.Replace("\"uid\":65534","\"uid\":0"),metadata.Replace("\"tasks_max\":16","\"tasks_max\":1"),metadata.Replace("\"runtime_cpu_seconds\":300","\"runtime_cpu_seconds\":30"),metadata.Replace("\"memory_max_bytes\":4831838208","\"memory_max_bytes\":536870912"),
            metadata.Replace("\"memory_swap_max_bytes\":0","\"memory_swap_max_bytes\":1"),metadata.Replace("\"inference_executed\":true","\"inference_executed\":false"),metadata.Replace("\"cap_effective\":\"0000000000000000\"","\"cap_effective\":\"0000000000000001\""),metadata.Replace("\"supplementary_groups\":[]","\"supplementary_groups\":[0]"),
            metadata.Replace("\"no_new_privileges\":true","\"no_new_privileges\":false"),metadata.Replace("\"schema_version\":1","\"schema_version\":true"),metadata.Replace("\"schema_version\":1","\"schema_version\":1,\"schema_version\":1"),metadata.Replace("\"max_tokens\":128","\"max_tokens\":512"),metadata.Replace("\"context_tokens\":2048","\"context_tokens\":8192")}) Refuse(delegate {GuestInferenceObservation.Validate(request,B(changed));});
        foreach(string name in new string[]{"principal_authenticated","grants_admitted","authority_returned","committed","workflow_executed","production_qualified"}) Refuse(delegate {GuestInferenceObservation.Validate(request,B(metadata.Replace("\""+name+"\":false","\""+name+"\":true")));});
        Require(Wire.Equal(Frames(request,metadata,result,0),result));foreach(int mode in new int[]{1,2,3,4}) Refuse(delegate {Frames(request,metadata,result,mode);});
        byte[] invalid=new byte[]{0xff};Refuse(delegate {Frames(request,Metadata(request,invalid),invalid,0);});
        string drain="{\"schema_version\":1,\"profile\":\""+GuestInferenceRequest.Profile+"\",\"unit\":\"luma-hosted-inference.service\",\"cgroup_empty_or_absent\":true,\"unit_inactive\":true,\"authority_returned\":false,\"job_completed\":false}";
        GuestInferenceObservation.ValidateDrain(B(drain));Require(true);
        foreach(string changed in new string[]{drain.Replace("inference","compute"),drain.Replace("\"cgroup_empty_or_absent\":true","\"cgroup_empty_or_absent\":false"),drain.Replace("\"unit_inactive\":true","\"unit_inactive\":false"),drain.Replace("\"job_completed\":false","\"job_completed\":true"),drain.Replace("\"authority_returned\":false","\"authority_returned\":true")}) Refuse(delegate {GuestInferenceObservation.ValidateDrain(B(changed));});
        string parent=Path.GetFullPath(Path.Combine(workspace,".luma"));Directory.CreateDirectory(parent);string root=Path.Combine(parent,"windows-inference-fixtures-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try {
            string path=Path.Combine(root,"request.json");File.WriteAllBytes(path,request.Bytes);Type type=typeof(GuestInferenceRequest).Assembly.GetType("Luma.Windows.Hosted.HostedInferenceInputs",true);
            using(IDisposable input=(IDisposable)Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{new string[]{"infer",H('1'),path}},null)) {
                type.GetMethod("Check",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(input,null);Require(true);
                bool denied=false;try {using(FileStream changed=new FileStream(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)) {}}catch(IOException) {denied=true;}Require(denied);
                FieldInfo cancel=type.GetField("cancel",BindingFlags.Instance|BindingFlags.NonPublic);((ConsoleCancelEventHandler)cancel.GetValue(input))(null,(ConsoleCancelEventArgs)System.Runtime.Serialization.FormatterServices.GetUninitializedObject(typeof(ConsoleCancelEventArgs)));
                bool cancelled=false;try {type.GetMethod("Check",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(input,null);}catch(TargetInvocationException error) {if(!(error.InnerException is OperationCanceledException)) throw;cancelled=true;}Require(cancelled);
            }
        }finally {string resolved=Path.GetFullPath(root);if(Path.GetDirectoryName(resolved)!=parent || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(resolved),"\\Awindows-inference-fixtures-[0-9a-f]{32}\\z")) throw new Exception("Refuse cleanup outside exact newly created inference fixture.");Directory.Delete(resolved,true);}
        return assertions;
    }
}
