using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Deliberately small parser for the exact flat guest observation object.
    // Duplicate keys, noninteger numbers and unbounded nesting are refused.
    internal sealed class ObservationJson
    {
        private readonly string input;private int at;private int nodes;
        private ObservationJson(byte[] bytes) {input=new UTF8Encoding(false,true).GetString(Wire.Copy(bytes,1,8192));}
        private void Space() {while(at<input.Length && (input[at]==' ' || input[at]=='\t' || input[at]=='\r' || input[at]=='\n')) at++;}
        private char Take() {if(at>=input.Length) throw new InvalidDataException("Truncated guest observation.");return input[at++];}
        private void Expect(char value) {Space();if(Take()!=value) throw new InvalidDataException("Guest observation JSON punctuation differs.");}
        private string Text()
        {
            Expect('"');StringBuilder value=new StringBuilder();
            while(true) {
                char c=Take();if(c=='"') break;if(c<' ') throw new InvalidDataException("Guest JSON string control refused.");
                if(c=='\\') {
                    c=Take();switch(c) {
                        case '"':case '\\':case '/':break;
                        case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;
                        case 'u':
                            int number=0;for(int index=0;index<4;index++) {char hex=Take();int part=hex>='0'&&hex<='9'?hex-'0':hex>='a'&&hex<='f'?hex-'a'+10:hex>='A'&&hex<='F'?hex-'A'+10:-1;
                                if(part<0) throw new InvalidDataException("Guest JSON Unicode escape differs.");number=(number<<4)|part;}c=(char)number;break;
                        default:throw new InvalidDataException("Guest JSON escape differs.");
                    }
                }
                value.Append(c);if(value.Length>4096) throw new InvalidDataException("Guest observation string exceeds bound.");
            }
            return value.ToString();
        }
        private object Value(int depth)
        {
            Space();if(++nodes>64 || depth>1 || at>=input.Length) throw new InvalidDataException("Guest observation exceeds structural bound.");char c=input[at];
            if(c=='"') return Text();
            if(c=='[') {
                at++;Space();List<ulong> values=new List<ulong>();if(at<input.Length && input[at]==']') {at++;return values;}
                while(true) {object value=Value(depth+1);if(!(value is ulong) || values.Count>=1) throw new InvalidDataException("Guest groups exceed closed bound.");values.Add((ulong)value);Space();char delimiter=Take();if(delimiter==']') return values;if(delimiter!=',') throw new InvalidDataException("Guest array delimiter differs.");}
            }
            if(c=='t' && at+4<=input.Length && input.Substring(at,4)=="true") {at+=4;return true;}
            if(c=='f' && at+5<=input.Length && input.Substring(at,5)=="false") {at+=5;return false;}
            int start=at;while(at<input.Length && input[at]>='0' && input[at]<='9') at++;
            if(at==start || at-start>20 || (at-start>1 && input[start]=='0')) throw new InvalidDataException("Guest numeric field must be canonical nonnegative integer.");
            ulong number;if(!UInt64.TryParse(input.Substring(start,at-start),System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out number)) throw new InvalidDataException("Guest numeric overflow.");return number;
        }
        internal static Dictionary<string,object> Parse(byte[] bytes)
        {
            ObservationJson parser=new ObservationJson(bytes);Dictionary<string,object> values=new Dictionary<string,object>(StringComparer.Ordinal);parser.Expect('{');parser.Space();
            if(parser.at<parser.input.Length && parser.input[parser.at]=='}') {parser.at++;parser.Space();if(parser.at!=parser.input.Length) throw new InvalidDataException("Trailing guest observation bytes.");return values;}
            while(true) {string key=parser.Text();parser.Expect(':');if(values.ContainsKey(key)) throw new InvalidDataException("Duplicate guest observation key.");values.Add(key,parser.Value(0));
                parser.Space();char delimiter=parser.Take();if(delimiter=='}') break;if(delimiter!=',') throw new InvalidDataException("Guest object delimiter differs.");}
            parser.Space();if(parser.at!=parser.input.Length) throw new InvalidDataException("Trailing guest observation bytes.");return values;
        }
    }

    public sealed class GuestComputeRequest
    {
        public const int MaximumEncoded=16*1024*1024;
        public const int MaximumResult=16*1024*1024;
        public const string Profile="luma-windows-hosted-compute-v1";
        public string Operation {get;private set;}
        public string Nonce {get;private set;}
        public string PayloadSha256 {get;private set;}
        private readonly byte[] encoded;
        public byte[] Bytes {get{return (byte[])encoded.Clone();}}
        public string RequestSha256 {get {using(SHA256 hash=SHA256.Create()) return Wire.Hex(hash.ComputeHash(encoded));}}
        public GuestComputeRequest(string operation,string payload)
        {
            if(operation!="capture" && operation!="reopen" && operation!="spreadsheet" && operation!="document" && operation!="diagram" && operation!="animation" && operation!="collection")
                throw new InvalidDataException("Guest compute operation is not allowlisted.");
            byte[] bytes=new UTF8Encoding(false,true).GetBytes(payload??"");
            if(bytes.Length<1 || bytes.Length>2*(1024*1024*6+8192)+8192) throw new InvalidDataException("Guest pure-contract payload exceeds its fixed bound.");
            Operation=operation;Nonce=Wire.Hex(Wire.Random(32));using(SHA256 hash=SHA256.Create()) PayloadSha256=Wire.Hex(hash.ComputeHash(bytes));
            string value="{\"schema_version\":1,\"profile\":"+Quote(Profile)+",\"nonce\":"+Quote(Nonce)+",\"operation\":"+Quote(operation)+
                ",\"payload\":"+Quote(payload)+",\"payload_sha256\":"+Quote(PayloadSha256)+"}";
            encoded=new UTF8Encoding(false,true).GetBytes(value);if(encoded.Length>MaximumEncoded) throw new InvalidDataException("Guest encoded request exceeds fixed transport bound.");
        }
        private static string Quote(string value)
        {
            StringBuilder result=new StringBuilder();result.Append('"');
            foreach(char c in value) {switch(c) {
                case '"':result.Append("\\\"");break;case '\\':result.Append("\\\\");break;
                case '\b':result.Append("\\b");break;case '\f':result.Append("\\f");break;case '\n':result.Append("\\n");break;case '\r':result.Append("\\r");break;case '\t':result.Append("\\t");break;
                default:if(c<' ') result.Append("\\u"+((int)c).ToString("x4"));else result.Append(c);break;
            }}result.Append('"');return result.ToString();
        }
    }

    public sealed class GuestComputeObservation
    {
        public string ResultSha256 {get;private set;}
        public int ResultBytes {get;private set;}
        public string Nonce {get;private set;}
        public string RequestSha256 {get;private set;}
        private GuestComputeObservation() {}
        public static GuestComputeObservation Validate(GuestComputeRequest request,byte[] metadata)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(metadata);
            string[] expected={"schema_version","profile","nonce","operation","request_sha256","payload_sha256","result_sha256","result_bytes",
                "uid","gid","supplementary_groups","cap_inheritable","cap_permitted","cap_effective","cap_bounding","cap_ambient","no_new_privileges",
                "apparmor_profile","cgroup","memory_max_bytes","memory_swap_max_bytes","tasks_max","cpu_quota_usec","cpu_period_usec","runtime_cpu_seconds",
                "principal_authenticated","grants_admitted","authority_returned","committed","workflow_executed","production_qualified"};
            if(fields.Count!=expected.Length) throw new SecurityException("Guest observation has missing or unknown fields.");
            foreach(string key in expected) if(!fields.ContainsKey(key)) throw new SecurityException("Guest observation omits a required field.");
            Func<string,string> text=delegate(string key) {object value=fields[key];if(!(value is string)) throw new SecurityException("Guest observation string type differs.");return (string)value;};
            Func<string,ulong> number=delegate(string key) {object value=fields[key];if(!(value is ulong)) throw new SecurityException("Guest observation integer type differs.");return (ulong)value;};
            Func<string,bool> boolean=delegate(string key) {object value=fields[key];if(!(value is bool)) throw new SecurityException("Guest observation boolean type differs.");return (bool)value;};
            if(number("schema_version")!=1 || text("profile")!=GuestComputeRequest.Profile || text("nonce")!=request.Nonce || text("operation")!=request.Operation ||
                text("request_sha256")!=request.RequestSha256 || text("payload_sha256")!=request.PayloadSha256 || number("uid")!=65534 || number("gid")!=65534 ||
                !boolean("no_new_privileges") || text("apparmor_profile")!="luma-hosted-compute" || text("cgroup")!="0::/lumahosted.slice/luma-hosted-compute.service\n" ||
                number("memory_max_bytes")!=512UL*1024*1024 || number("memory_swap_max_bytes")!=0 || number("tasks_max")!=1 ||
                number("cpu_quota_usec")!=100000 || number("cpu_period_usec")!=100000 || number("runtime_cpu_seconds")!=30)
                throw new SecurityException("Guest actual confinement differs from the fixed hosted compute profile.");
            foreach(string name in new string[]{"cap_inheritable","cap_permitted","cap_effective","cap_bounding","cap_ambient"}) if(text(name)!="0000000000000000") throw new SecurityException("Guest retains capabilities.");
            foreach(string name in new string[]{"principal_authenticated","grants_admitted","authority_returned","committed","workflow_executed","production_qualified"})
                if(boolean(name)) throw new SecurityException("Guest data engine claims host or Linux product authority.");
            List<ulong> groups=fields["supplementary_groups"] as List<ulong>;
            if(groups==null || groups.Count>1 || (groups.Count==1 && groups[0]!=65534)) throw new SecurityException("Guest supplementary group set differs.");
            ulong bytes=number("result_bytes");if(bytes<1 || bytes>GuestComputeRequest.MaximumResult) throw new SecurityException("Guest result exceeds bound.");
            string digest=text("result_sha256");Wire.Bytes(digest,32,true);
            return new GuestComputeObservation {ResultSha256=digest,ResultBytes=(int)bytes,Nonce=request.Nonce,RequestSha256=request.RequestSha256};
        }
    }

    public static class GuestDrainObservation
    {
        public static void Validate(byte[] metadata)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(metadata);
            string[] expected={"schema_version","profile","unit","cgroup_empty_or_absent","unit_inactive","authority_returned","job_completed"};
            if(fields.Count!=expected.Length) throw new SecurityException("Guest drain observation field count differs.");
            foreach(string name in expected) if(!fields.ContainsKey(name)) throw new SecurityException("Guest drain observation omits a field.");
            if(!(fields["schema_version"] is ulong) || (ulong)fields["schema_version"]!=1 ||
                !(fields["profile"] is string) || (string)fields["profile"]!=GuestComputeRequest.Profile ||
                !(fields["unit"] is string) || (string)fields["unit"]!="luma-hosted-compute.service")
                throw new SecurityException("Guest drain observer identity differs.");
            foreach(string name in new string[]{"cgroup_empty_or_absent","unit_inactive"})
                if(!(fields[name] is bool) || !(bool)fields[name]) throw new SecurityException("Guest compute resources remain active or unobserved.");
            foreach(string name in new string[]{"authority_returned","job_completed"})
                if(!(fields[name] is bool) || (bool)fields[name]) throw new SecurityException("Drain observation claims authority or successful execution.");
        }
    }

    // The codec has no execution or publication authority. The live callback is
    // required before every transfer and before acknowledging any result bytes.
    // Results are delivered only after the entire advertised digest is checked.
    public static class GuestComputeFrames
    {
        private static readonly byte[] Magic=Encoding.ASCII.GetBytes("LUMAWINCOMPv1!!\n");
        public static byte[] Length(uint value)
        {return new byte[]{unchecked((byte)(value>>24)),unchecked((byte)(value>>16)),unchecked((byte)(value>>8)),unchecked((byte)value)};}
        private static uint Number(byte[] bytes)
        {return ((uint)bytes[0]<<24)|((uint)bytes[1]<<16)|((uint)bytes[2]<<8)|bytes[3];}
        internal static T Await<T>(Task<T> task,Action check,Stopwatch deadline,TimeSpan maximum)
        {
            while(!task.IsCompleted) {check();if(deadline.Elapsed>=maximum) throw new IOException("Hosted compute I/O deadline expired.");System.Threading.Thread.Sleep(25);}
            check();if(deadline.Elapsed>=maximum) throw new IOException("Hosted compute I/O deadline expired.");return task.GetAwaiter().GetResult();
        }
        private static byte[] Exact(Stream input,int count,Action check,Stopwatch deadline,TimeSpan maximum)
        {
            byte[] bytes=new byte[count];int at=0;
            while(at<count) {check();int offset=at,length=Math.Min(32768,count-at);
                int read=Await(Task.Factory.StartNew(delegate {return input.Read(bytes,offset,length);}),check,deadline,maximum);
                if(read<1 || read>length) throw new EndOfStreamException("Hosted compute response truncated.");at+=read;}
            return bytes;
        }
        private static void Send(Stream output,byte[] bytes,Action check,Stopwatch deadline,TimeSpan maximum)
        {
            int at=0;while(at<bytes.Length) {check();int offset=at,count=Math.Min(32768,bytes.Length-at);
                Await(Task.Factory.StartNew(delegate {output.Write(bytes,offset,count);output.Flush();return true;}),check,deadline,maximum);at+=count;}
        }
        public static byte[] Exchange(GuestComputeRequest request,Stream input,Stream output,Action check)
        {
            if(request==null || input==null || output==null || check==null) throw new ArgumentNullException("Fixed hosted compute exchange input.");
            Stopwatch deadline=Stopwatch.StartNew();TimeSpan maximum=TimeSpan.FromSeconds(30);check();
            byte[] wire=request.Bytes;Send(output,Length((uint)wire.Length),check,deadline,maximum);Send(output,wire,check,deadline,maximum);
            if(!Wire.Equal(Exact(input,Magic.Length,check,deadline,maximum),Magic)) throw new InvalidDataException("Hosted compute frame magic differs.");
            uint metadataLength=Number(Exact(input,4,check,deadline,maximum));
            if(metadataLength<1 || metadataLength>8192) throw new InvalidDataException("Hosted compute metadata exceeds its bound.");
            GuestComputeObservation observation=GuestComputeObservation.Validate(request,Exact(input,(int)metadataLength,check,deadline,maximum));
            byte[] result=new byte[observation.ResultBytes];int at=0;
            using(SHA256 running=SHA256.Create()) {
                while(at<result.Length) {
                    byte[] part=Exact(input,Math.Min(32768,result.Length-at),check,deadline,maximum);Buffer.BlockCopy(part,0,result,at,part.Length);at+=part.Length;
                    // SHA256 instances cannot be cloned. A bounded cumulative
                    // hash matches the fixed guest acknowledgement protocol.
                    byte[] digest=running.ComputeHash(result,0,at);byte[] acknowledgement=new byte[40];ulong total=(ulong)at;
                    for(int index=0;index<8;index++) acknowledgement[index]=unchecked((byte)(total>>(56-index*8)));
                    Buffer.BlockCopy(digest,0,acknowledgement,8,32);check();Send(output,acknowledgement,check,deadline,maximum);
                }
                if(Wire.Hex(running.ComputeHash(result))!=observation.ResultSha256) throw new SecurityException("Hosted compute full result hash differs.");
            }
            if(ExactEnd(input,check,deadline,maximum)!=-1) throw new InvalidDataException("Hosted compute output has unadvertised bytes.");check();return result;
        }
        internal static int ExactEnd(Stream input,Action check,Stopwatch deadline,TimeSpan maximum)
        {return Await(Task.Factory.StartNew(delegate {return input.ReadByte();}),check,deadline,maximum);}
        internal static byte[] BoundedEnd(Stream input,int limit,Action check,Stopwatch deadline,TimeSpan maximum)
        {
            using(MemoryStream output=new MemoryStream()) {
                byte[] block=new byte[Math.Min(4096,limit+1)];while(true) {
                    int count=Await(Task.Factory.StartNew(delegate {return input.Read(block,0,Math.Min(block.Length,limit-(int)output.Length+1));}),check,deadline,maximum);
                    if(count==0) break;if(output.Length+count>limit) throw new InvalidDataException("Hosted observer or diagnostic output exceeds its fixed bound.");output.Write(block,0,count);
                }return output.ToArray();
            }
        }
    }

    internal sealed class PinnedWsl : IDisposable
    {
        private readonly InstalledInputLease lease;
        internal string Path {get;private set;}
        internal PinnedWsl(string expected)
        {
            FixedServiceIdentity.Require();Wire.Bytes(expected,32,true);Path=System.IO.Path.Combine(Environment.SystemDirectory,"wsl.exe");
            lease=InstalledInputLease.Acquire(Path);
            try {
                if(lease.Length<64 || lease.Length>128*1024*1024) throw new SecurityException("Fixed WSL executable length differs.");
                Check();string actual;using(SHA256 hash=SHA256.Create()) actual=Wire.Hex(hash.ComputeHash(lease.Rewind()));
                if(actual!=expected) throw new SecurityException("Commissioned WSL runtime changed; no dependency fallback.");Check();
            }
            catch {lease.Dispose();throw;}
        }
        internal void Check()
        {
            // Held no-follow file/ancestor handles deny write and replacement.
            // Recheck those exact objects continuously; do not rehash tens of
            // megabytes for every 32-KiB transport acknowledgement.
            FixedServiceIdentity.Require();lease.Check();
        }
        public void Dispose() {lease.Dispose();}
    }

    // Owns one exact suspended child before it can execute. A job close kills
    // that controller only; guest drainage is separately observed, not assumed.
    internal sealed class OwnedWindowsProcess : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {public int Length;public IntPtr Descriptor;public int Inherit;}
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Startup {
            public int Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;public ushort Show,ReservedBytes;public IntPtr ReservedData,Input,Output,Error;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {public IntPtr Process,Thread;public uint Pid,Tid;}
        [StructLayout(LayoutKind.Sequential)] private struct StartupEx {public Startup Startup;public IntPtr Attributes;}
        [StructLayout(LayoutKind.Sequential)] private struct IoCounters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
        [StructLayout(LayoutKind.Sequential)] private struct BasicLimits {public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinWorking,MaxWorking;public uint Processes;public UIntPtr Affinity;public uint Priority,Scheduling;}
        [StructLayout(LayoutKind.Sequential)] private struct Limits {public BasicLimits Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;}
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,ref SecurityAttributes attributes,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetHandleInformation(SafeFileHandle handle,uint mask,uint flags);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool CreateRestrictedToken(SafeAccessTokenHandle token,uint flags,uint disabledCount,IntPtr disabled,uint deletedCount,IntPtr deleted,uint restrictedCount,IntPtr restricted,out SafeAccessTokenHandle result);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token,uint access,IntPtr attributes,int level,int kind,out SafeAccessTokenHandle result);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool SetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr information,uint bytes);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token,string application,StringBuilder arguments,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo process);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref UIntPtr bytes);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,UIntPtr bytes,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateJobObject(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetInformationJobObject(SafeFileHandle job,int kind,ref Limits limits,uint bytes);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job,SafeWaitHandle process);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateJobObject(SafeFileHandle job,uint exit);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeWaitHandle handle,uint timeout);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetExitCodeProcess(SafeWaitHandle process,out uint code);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeWaitHandle OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetProcessTimes(SafeWaitHandle process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
        private SafeFileHandle job;private SafeWaitHandle process;private FileStream input,output,error;
        internal Stream Input {get{return input;}}
        internal Stream Output {get{return output;}}
        internal Stream Error {get{return error;}}
        internal uint Id {get;private set;}
        internal ulong Creation {get;private set;}
        private OwnedWindowsProcess() {}
        internal static string Argument(string value)
        {
            if(value==null || value.Length>1024 || value.IndexOf('\0')>=0 || value.IndexOf('\r')>=0 || value.IndexOf('\n')>=0) throw new InvalidDataException("WSL argument exceeds fixed inert bound.");
            StringBuilder quoted=new StringBuilder("\"");int slashes=0;
            foreach(char c in value) {if(c=='\\') {slashes++;continue;}if(c=='"') {quoted.Append('\\',slashes*2+1);quoted.Append('"');slashes=0;continue;}quoted.Append('\\',slashes);slashes=0;quoted.Append(c);}
            quoted.Append('\\',slashes*2);quoted.Append('"');return quoted.ToString();
        }
        private static SafeAccessTokenHandle Restricted(SafeAccessTokenHandle actor)
        {
            SafeAccessTokenHandle primary,restricted=null;
            if(!DuplicateTokenEx(actor,0xF01FF,IntPtr.Zero,2,1,out primary)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                if(!CreateRestrictedToken(primary,1|4,0,IntPtr.Zero,0,IntPtr.Zero,0,IntPtr.Zero,out restricted)) throw new Win32Exception(Marshal.GetLastWin32Error());
                SecurityIdentifier medium=new SecurityIdentifier("S-1-16-8192");byte[] sid=new byte[medium.BinaryLength];medium.GetBinaryForm(sid,0);
                int header=IntPtr.Size==8?16:8;IntPtr label=Marshal.AllocHGlobal(header+sid.Length);
                try {for(int index=0;index<header+sid.Length;index++) Marshal.WriteByte(label,index,0);
                    IntPtr actual=IntPtr.Add(label,header);Marshal.Copy(sid,0,actual,sid.Length);Marshal.WriteIntPtr(label,actual);Marshal.WriteInt32(label,IntPtr.Size,0x20);
                    if(!SetTokenInformation(restricted,25,label,(uint)(header+sid.Length))) throw new Win32Exception(Marshal.GetLastWin32Error());
                } finally {Marshal.FreeHGlobal(label);}
                using(System.Security.Principal.WindowsIdentity identity=new System.Security.Principal.WindowsIdentity(restricted.DangerousGetHandle()))
                    if(new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)) throw new SecurityException("WSL controller retained enabled Windows Admin role.");
                return restricted;
            } catch {if(restricted!=null) restricted.Dispose();throw;}
            finally {primary.Dispose();}
        }
        internal static OwnedWindowsProcess Start(PinnedWsl binary,HostedActor actor,string[] arguments,Action<OwnedWindowsProcess> beforeResume)
        {
            FixedServiceIdentity.Require();actor.Check();binary.Check();if(arguments==null || arguments.Length>12 || beforeResume==null) throw new InvalidDataException("Closed WSL invocation shape or pre-execution registration differs.");
            StringBuilder command=new StringBuilder(Argument(binary.Path));foreach(string argument in arguments) command.Append(" "+Argument(argument));
            OwnedWindowsProcess result=new OwnedWindowsProcess();SafeFileHandle childInput=null,childOutput=null,childError=null,parentInput=null,parentOutput=null,parentError=null;
            ProcessInfo created=new ProcessInfo();bool assigned=false;
            try {
                SecurityAttributes attributes=new SecurityAttributes {Length=Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=1};
                if(!CreatePipe(out childInput,out parentInput,ref attributes,65536) || !CreatePipe(out parentOutput,out childOutput,ref attributes,65536) ||
                    !CreatePipe(out parentError,out childError,ref attributes,4096)) throw new Win32Exception(Marshal.GetLastWin32Error());
                foreach(SafeFileHandle handle in new SafeFileHandle[]{parentInput,parentOutput,parentError}) if(!SetHandleInformation(handle,1,0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                result.job=CreateJobObject(IntPtr.Zero,null);if(result.job.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                Limits limits=new Limits();limits.Basic.Flags=0x2000|0x200|0x8|0x400;limits.Basic.Processes=4;limits.JobMemory=(UIntPtr)(512UL*1024*1024);
                if(!SetInformationJobObject(result.job,9,ref limits,(uint)Marshal.SizeOf(typeof(Limits)))) throw new Win32Exception(Marshal.GetLastWin32Error());
                StartupEx startup=new StartupEx();startup.Startup=new Startup {Size=Marshal.SizeOf(typeof(StartupEx)),Flags=0x100,Input=childInput.DangerousGetHandle(),Output=childOutput.DangerousGetHandle(),Error=childError.DangerousGetHandle(),Desktop="winsta0\\default"};
                // The environment is fixed, not inherited from the service or
                // caller. No Windows executable or shell is chosen by a guest.
                string block="LANG=C.UTF-8\0LC_ALL=C.UTF-8\0PATH="+Environment.SystemDirectory+"\0SystemRoot="+Environment.GetFolderPath(Environment.SpecialFolder.Windows)+"\0\0";
                IntPtr environment=Marshal.StringToHGlobalUni(block);
                IntPtr inheritList=IntPtr.Zero;bool initialized=false;
                try {
                    UIntPtr needed=UIntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref needed);
                    if(needed.ToUInt64()<1 || needed.ToUInt64()>65536) throw new SecurityException("Process attribute-list size differs.");
                    startup.Attributes=Marshal.AllocHGlobal((int)needed.ToUInt64());
                    if(!InitializeProcThreadAttributeList(startup.Attributes,1,0,ref needed)) throw new Win32Exception(Marshal.GetLastWin32Error());initialized=true;
                    inheritList=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(inheritList,0,childInput.DangerousGetHandle());
                    Marshal.WriteIntPtr(inheritList,IntPtr.Size,childOutput.DangerousGetHandle());Marshal.WriteIntPtr(inheritList,IntPtr.Size*2,childError.DangerousGetHandle());
                    if(!UpdateProcThreadAttribute(startup.Attributes,0,(IntPtr)0x20002,inheritList,(UIntPtr)(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    using(SafeAccessTokenHandle restricted=Restricted(actor.Token)) {
                        if(!CreateProcessAsUser(restricted,binary.Path,command,IntPtr.Zero,IntPtr.Zero,true,4|0x400|0x08000000|0x80000,environment,Environment.SystemDirectory,ref startup,out created))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                } finally {
                    if(inheritList!=IntPtr.Zero) Marshal.FreeHGlobal(inheritList);
                    if(initialized) DeleteProcThreadAttributeList(startup.Attributes);
                    if(startup.Attributes!=IntPtr.Zero) Marshal.FreeHGlobal(startup.Attributes);Marshal.FreeHGlobal(environment);
                }
                result.process=new SafeWaitHandle(created.Process,true);created.Process=IntPtr.Zero;
                result.Id=created.Pid;long creation,exit,kernel,user;
                if(!GetProcessTimes(result.process,out creation,out exit,out kernel,out user) || creation<=0) throw new Win32Exception(Marshal.GetLastWin32Error());result.Creation=(ulong)creation;
                using(SafeWaitHandle thread=new SafeWaitHandle(created.Thread,true)) {created.Thread=IntPtr.Zero;
                    if(!AssignProcessToJobObject(result.job,result.process)) throw new Win32Exception(Marshal.GetLastWin32Error());assigned=true;
                    actor.Check();binary.Check();beforeResume(result);actor.Check();if(ResumeThread(thread)==UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                childInput.Dispose();childInput=null;childOutput.Dispose();childOutput=null;childError.Dispose();childError=null;
                result.input=new FileStream(parentInput,FileAccess.Write,4096,false);parentInput=null;
                result.output=new FileStream(parentOutput,FileAccess.Read,4096,false);parentOutput=null;
                result.error=new FileStream(parentError,FileAccess.Read,4096,false);parentError=null;return result;
            } catch {
                // A suspended child not assigned to the job is still owned.
                // Close its sole thread without resume and terminate by handle.
                try {if(!assigned && result.process!=null && !result.process.IsInvalid) NativeTerminate(result.process);}
                finally {result.Dispose();}throw;
            } finally {
                foreach(SafeFileHandle handle in new SafeFileHandle[]{childInput,childOutput,childError,parentInput,parentOutput,parentError}) if(handle!=null) handle.Dispose();
                if(created.Thread!=IntPtr.Zero) CloseHandle(created.Thread);if(created.Process!=IntPtr.Zero) CloseHandle(created.Process);
            }
        }
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(SafeWaitHandle process,uint code);
        private static void NativeTerminate(SafeWaitHandle value) {if(!TerminateProcess(value,1) && WaitForSingleObject(value,0)!=0) throw new Win32Exception(Marshal.GetLastWin32Error());}
        internal bool Exited {get{return WaitForSingleObject(process,0)==0;}}
        internal static bool OriginalExited(uint pid,ulong creation)
        {
            if(pid<4 || creation<1) throw new SecurityException("Original controller process binding is missing.");
            using(SafeWaitHandle handle=OpenProcess(0x1000|0x100000,false,pid)) {
                if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();if(error==87) return true;throw new Win32Exception(error);}
                long created,exited,kernel,user;if(!GetProcessTimes(handle,out created,out exited,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return unchecked((ulong)created)!=creation || WaitForSingleObject(handle,0)==0;
            }
        }
        internal void RequireSuccess(Action check,TimeSpan maximum)
        {
            Stopwatch deadline=Stopwatch.StartNew();while(!Exited) {check();if(deadline.Elapsed>=maximum) throw new IOException("Owned WSL controller runtime expired; guest drainage unconfirmed.");System.Threading.Thread.Sleep(100);}
            uint code;if(!GetExitCodeProcess(process,out code)) throw new Win32Exception(Marshal.GetLastWin32Error());if(code!=0) throw new IOException("Actual fixed WSL controller refused the operation.");check();
        }
        public void Dispose()
        {
            if(input!=null){input.Dispose();input=null;}
            if(job!=null && !job.IsInvalid) {TerminateJobObject(job,1);job.Dispose();job=null;}
            if(output!=null){output.Dispose();output=null;}if(error!=null){error.Dispose();error=null;}
            if(process!=null){WaitForSingleObject(process,3000);process.Dispose();process=null;}
        }
    }

    internal static class HostedGuestRunner
    {
        internal static string Distribution(AuthorityIdentity identity,DeploymentEvent admission)
        {
            if(identity.Domain!="host-deployment" || admission==null) throw new SecurityException("Hosted slot identity or exact source admission is missing.");
            return "LumaHosted-"+identity.Installation+"-"+admission.ReleaseSequence.ToString(System.Globalization.CultureInfo.InvariantCulture)+"-"+admission.PackageLeaf.Substring("ticket-package-".Length,32);
        }
        private static string[] Arguments(string distribution,string operation)
        {
            if(distribution==null || distribution.Length>128 || !System.Text.RegularExpressions.Regex.IsMatch(distribution,@"\ALumaHosted-[0-9a-f]{64}-[1-9][0-9]{0,15}-[0-9a-f]{32}\z"))
                throw new SecurityException("Hosted distribution is not an installation-owned slot.");
            if(operation!="hosted-windows-compute-launch" && operation!="hosted-windows-compute-drain") throw new SecurityException("Hosted process operation is not fixed.");
            return new string[]{"--distribution",distribution,"--user","root","--exec","/usr/libexec/luma-os/luma-platform",operation};
        }
        private static Task<byte[]> Diagnostics(Stream input)
        {
            // Diagnostic bytes never carry authority and are never reflected
            // into command selection or user-visible execution success.
            return Task.Factory.StartNew(delegate {
                using(MemoryStream bytes=new MemoryStream()) {
                    byte[] part=new byte[1024];while(true) {int read=input.Read(part,0,Math.Min(part.Length,4097-(int)bytes.Length));
                        if(read==0) return bytes.ToArray();if(bytes.Length+read>4096) throw new InvalidDataException("Fixed WSL diagnostics exceeded their bound.");bytes.Write(part,0,read);}
                }
            });
        }
        private static Action Checked(HostedActor actor,PinnedWsl binary,Action live,Task<byte[]> errors)
        {
            return delegate {
                actor.Check();binary.Check();live();
                if(errors.IsFaulted) errors.GetAwaiter().GetResult();
                if(errors.IsCanceled) throw new IOException("Owned WSL diagnostic capture was cancelled.");
            };
        }
        internal static byte[] Compute(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,GuestComputeRequest request,Action<OwnedWindowsProcess> beforeResume,Action live)
        {
            if(live==null) throw new ArgumentNullException("live");string distribution=Distribution(identity,admission);live();actor.Check();
            byte[] result;
            using(PinnedWsl binary=new PinnedWsl(identity.WslSha256)) {
                using(OwnedWindowsProcess controller=OwnedWindowsProcess.Start(binary,actor,Arguments(distribution,"hosted-windows-compute-launch"),beforeResume)) {
                    Task<byte[]> errors=Diagnostics(controller.Error);Action check=Checked(actor,binary,live,errors);
                    // The caller's resource generation is already durably
                    // reserved before this invocation. Any exception leaves it
                    // reserved until a separately authenticated drain review.
                    result=GuestComputeFrames.Exchange(request,controller.Output,controller.Input,check);
                    controller.Input.Close();controller.RequireSuccess(check,TimeSpan.FromSeconds(1));
                    GuestComputeFrames.Await(errors,check,Stopwatch.StartNew(),TimeSpan.FromSeconds(1));
                    if(!controller.Exited) throw new SecurityException("Original WSL controller exit is unobserved.");
                }
                Drain(binary,actor,distribution,live);
            }
            live();return result;
        }
        internal static void Drain(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,Action live)
        {
            using(PinnedWsl binary=new PinnedWsl(identity.WslSha256)) Drain(binary,actor,Distribution(identity,admission),live);
        }
        private static void Drain(PinnedWsl binary,HostedActor actor,string distribution,Action live)
        {
            actor.Check();live();using(OwnedWindowsProcess observer=OwnedWindowsProcess.Start(binary,actor,Arguments(distribution,"hosted-windows-compute-drain"),delegate(OwnedWindowsProcess process) {live();})) {
                observer.Input.Close();Task<byte[]> errors=Diagnostics(observer.Error);Action check=Checked(actor,binary,live,errors);Stopwatch deadline=Stopwatch.StartNew();
                byte[] observation=GuestComputeFrames.BoundedEnd(observer.Output,8192,check,deadline,TimeSpan.FromSeconds(5));
                observer.RequireSuccess(check,TimeSpan.FromSeconds(1));GuestComputeFrames.Await(errors,check,deadline,TimeSpan.FromSeconds(5));
                GuestDrainObservation.Validate(observation);if(!observer.Exited) throw new SecurityException("Read-only guest drain observer has not exited.");check();
            }
        }
    }

    internal static class HostedWslConfiguration
    {
        // Official per-user WSL API, never an HKCU string supplied by a caller.
        // https://learn.microsoft.com/windows/win32/api/wslapi/
        [DllImport("api-ms-win-wsl-api-l1-1-0.dll",CharSet=CharSet.Unicode)]
        [return:MarshalAs(UnmanagedType.Bool)] private static extern bool WslIsDistributionRegistered(string distribution);
        [DllImport("api-ms-win-wsl-api-l1-1-0.dll",CharSet=CharSet.Unicode)] private static extern int WslGetDistributionConfiguration(string distribution,out uint version,out uint uid,out uint flags,out IntPtr variables,out uint count);
        [DllImport("api-ms-win-wsl-api-l1-1-0.dll",CharSet=CharSet.Unicode)] private static extern int WslConfigureDistribution(string distribution,uint uid,uint flags);
        private static void ImpersonatedIdentity(HostedActor actor)
        {
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) if(identity.User==null || identity.User.Value!=actor.Sid || identity.ImpersonationLevel!=TokenImpersonationLevel.Impersonation)
                throw new SecurityException("Actual WSL API caller is not the original captured interactive account.");
        }
        internal static bool Registered(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission)
        {
            FixedServiceIdentity.Require();actor.RequireAdmin(identity.FirstAdminSid);string distribution=HostedGuestRunner.Distribution(identity,admission);
            bool registered=WindowsIdentity.RunImpersonated(actor.Token,delegate {ImpersonatedIdentity(actor);return WslIsDistributionRegistered(distribution);});
            FixedServiceIdentity.Require();actor.Check();return registered;
        }
        internal static void RequireClosed(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission)
        {
            FixedServiceIdentity.Require();actor.RequireAdmin(identity.FirstAdminSid);string distribution=HostedGuestRunner.Distribution(identity,admission);
            WindowsIdentity.RunImpersonated(actor.Token,delegate {
                ImpersonatedIdentity(actor);if(!WslIsDistributionRegistered(distribution)) throw new SecurityException("Exact installation-owned WSL slot is absent.");
                uint version,uid,flags,count;IntPtr environment;int result=WslGetDistributionConfiguration(distribution,out version,out uid,out flags,out environment,out count);
                try {
                    if(result!=0 || version!=2 || uid!=65534 || flags!=0 || count>128) throw new SecurityException("Actual owned WSL slot is not version2/defaultnobody/zero interop-path-drive flags.");
                } finally {
                    if(environment!=IntPtr.Zero) {
                        try {for(uint index=0;index<count;index++) {
                            IntPtr value=Marshal.ReadIntPtr(environment,checked((int)index*IntPtr.Size));if(value!=IntPtr.Zero) Marshal.FreeCoTaskMem(value);
                        }} finally {Marshal.FreeCoTaskMem(environment);}
                    }
                }
            });
            FixedServiceIdentity.Require();actor.Check();
        }
        internal static void ConfigureNew(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,Action check)
        {
            check();FixedServiceIdentity.Require();actor.RequireAdmin(identity.FirstAdminSid);string distribution=HostedGuestRunner.Distribution(identity,admission);
            WindowsIdentity.RunImpersonated(actor.Token,delegate {
                ImpersonatedIdentity(actor);if(!WslIsDistributionRegistered(distribution)) throw new SecurityException("Newly imported owned slot is not registered.");
                int result=WslConfigureDistribution(distribution,65534,0);
                if(result!=0) throw new SecurityException("Actual owned WSL interop/path/drive/default-user configuration refused: 0x"+unchecked((uint)result).ToString("x8"));
            });
            FixedServiceIdentity.Require();check();RequireClosed(identity,actor,admission);
        }
    }
}
