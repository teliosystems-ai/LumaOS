using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    internal static class HostedPipe
    {
        internal const string Name="LumaOS.HostedAuthority.v1";
        [StructLayout(LayoutKind.Sequential)] private struct Attributes {public int Length;public IntPtr Descriptor;public int Inherit;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafePipeHandle CreateNamedPipe(string name,uint mode,uint pipeMode,uint instances,uint output,uint input,uint timeout,ref Attributes attributes);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool CancelIoEx(SafePipeHandle pipe,IntPtr overlapped);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [StructLayout(LayoutKind.Sequential)] private struct Status {public uint Type,State,Controls,Win32,Service,Checkpoint,Hint,Pid,Flags;}
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool QueryServiceStatusEx(IntPtr service,int level,out Status status,int bytes,out int needed);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        internal static NamedPipeServerStream Create()
        {
            FixedServiceIdentity.Require();SecurityIdentifier service=(SecurityIdentifier)new NTAccount("NT SERVICE",FixedServiceIdentity.Name).Translate(typeof(SecurityIdentifier));
            // Remote/network clients are denied both by the kernel pipe flag and
            // DACL. Actual client identity is still inspected after connection.
            RawSecurityDescriptor descriptor=new RawSecurityDescriptor("O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;"+service.Value+")(A;;GRGW;;;IU)");
            byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);GCHandle pin=GCHandle.Alloc(bytes,GCHandleType.Pinned);
            try {
                Attributes attributes=new Attributes {Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=pin.AddrOfPinnedObject(),Inherit=0};
                // FIRST_PIPE_INSTANCE prevents a pre-existing endpoint from
                // being adopted; REJECT_REMOTE_CLIENTS is not a name heuristic.
                SafePipeHandle handle=CreateNamedPipe(@"\\.\pipe\"+Name,3|0x40000000|0x80000,8,1,65536,65536,0,ref attributes);
                if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
                try {return new NamedPipeServerStream(PipeDirection.InOut,true,false,handle);} catch {handle.Dispose();throw;}
            } finally {pin.Free();}
        }
        internal static uint ClientPid(NamedPipeServerStream pipe)
        {uint pid;if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid) || pid==0) throw new Win32Exception(Marshal.GetLastWin32Error());return pid;}
        internal static void CheckServer(NamedPipeClientStream pipe)
        {
            uint pid;if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid) || pid==0) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr manager=IntPtr.Zero,service=IntPtr.Zero;
            try {
                manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                service=OpenService(manager,FixedServiceIdentity.Name,4);if(service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                Status status;int needed;
                if(!QueryServiceStatusEx(service,0,out status,Marshal.SizeOf(typeof(Status)),out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(needed>Marshal.SizeOf(typeof(Status)) || status.Type!=0x10 || status.State!=4 || status.Pid!=pid)
                    throw new SecurityException("Pipe server is not the actual fixed running own-process service.");
            } finally {if(service!=IntPtr.Zero) CloseServiceHandle(service);if(manager!=IntPtr.Zero) CloseServiceHandle(manager);}
        }
        private static void Wait(PipeStream pipe,Task task,Stopwatch deadline,TimeSpan maximum,Action check)
        {
            while(!task.Wait(100)) {
                check();if(deadline.Elapsed>=maximum) {
                    CancelIoEx(pipe.SafePipeHandle,IntPtr.Zero);
                    if(!task.Wait(2000)) pipe.Dispose();
                    throw new IOException("Actual bounded pipe operation timed out; effect outcome is not inferred.");
                }
            }
            check();task.GetAwaiter().GetResult();
        }
        internal static void ReadExact(PipeStream pipe,byte[] bytes,Action check,TimeSpan maximum)
        {
            Stopwatch deadline=Stopwatch.StartNew();int at=0;
            while(at<bytes.Length) {
                check();Task<int> read=pipe.ReadAsync(bytes,at,Math.Min(32768,bytes.Length-at));Wait(pipe,read,deadline,maximum,check);
                int count=read.Result;if(count==0) throw new EndOfStreamException("Original authenticated pipe client disconnected.");at+=count;
            }
        }
        internal static byte[] Read(PipeStream pipe,Action check,TimeSpan maximum)
        {
            byte[] length=new byte[4];ReadExact(pipe,length,check,maximum);
            uint count=((uint)length[0]<<24)|((uint)length[1]<<16)|((uint)length[2]<<8)|length[3];
            if(count<1 || count>Wire.MaximumFrame-4) throw new InvalidDataException("Hosted pipe frame exceeds its closed bound.");
            byte[] result=new byte[count];ReadExact(pipe,result,check,maximum);return result;
        }
        internal static void Write(PipeStream pipe,byte[] bytes,Action check,TimeSpan maximum)
        {
            Wire.Copy(bytes,1,Wire.MaximumFrame-4);uint count=(uint)bytes.Length;
            byte[] frame=Wire.Join(new byte[]{(byte)(count>>24),(byte)(count>>16),unchecked((byte)(count>>8)),unchecked((byte)count)},bytes);
            try {
                Stopwatch deadline=Stopwatch.StartNew();int at=0;
                while(at<frame.Length) {check();int size=Math.Min(32768,frame.Length-at);Task write=pipe.WriteAsync(frame,at,size);Wait(pipe,write,deadline,maximum,check);at+=size;}
                check();
            } finally {Array.Clear(frame,0,frame.Length);}
        }
    }

    internal sealed class HostedActor : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Luid {public uint Low;public int High;}
        [StructLayout(LayoutKind.Sequential)] private struct Statistics {
            public Luid TokenId,AuthenticationId;public long Expiration;public uint TokenType,ImpersonationLevel,DynamicCharged,DynamicAvailable,GroupCount,PrivilegeCount;public Luid ModifiedId;
        }
        [StructLayout(LayoutKind.Sequential)] private struct UserInfo {
            public IntPtr Name,Password;public uint PasswordAge,Privilege;public IntPtr Home,Comment;public uint Flags;public IntPtr Script;
        }
        [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeWaitHandle OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeWaitHandle handle,uint timeout);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(SafeWaitHandle process,uint access,out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr output,uint bytes,out uint needed);
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] private static extern uint NetUserGetInfo(string server,string name,uint level,out IntPtr buffer);
        [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);
        [DllImport("wtsapi32.dll",SetLastError=true)] private static extern bool WTSQuerySessionInformation(IntPtr server,uint session,int kind,out IntPtr buffer,out uint bytes);
        [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr buffer);
        private readonly NamedPipeServerStream pipe;private readonly SafeWaitHandle process;private readonly SafeAccessTokenHandle token;
        private readonly Statistics original;private readonly Stopwatch age=Stopwatch.StartNew();
        internal string Sid {get;private set;}
        internal uint Session {get;private set;}
        internal bool Administrator {get;private set;}
        internal SafeAccessTokenHandle Token {get{return token;}}
        private HostedActor(NamedPipeServerStream pipe,SafeWaitHandle process,SafeAccessTokenHandle token,string observedSid,Luid observedLogon,bool observedAdmin)
        {
            this.pipe=pipe;this.process=process;this.token=token;
            using(WindowsIdentity identity=new WindowsIdentity(token.DangerousGetHandle())) {
                if(identity.User==null || identity.User.Value!=observedSid || !identity.IsAuthenticated) throw new SecurityException("Pipe impersonation and actual primary token differ.");
                WindowsPrincipal principal=new WindowsPrincipal(identity);
                if(!principal.IsInRole(new SecurityIdentifier("S-1-5-4"))) throw new SecurityException("Actual interactive Windows logon token required.");
                Sid=Wire.Sid(identity.User.Value);Administrator=principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            Session=Number(12);original=Stats();
            if(!Same(original.AuthenticationId,observedLogon) || Administrator!=observedAdmin) throw new SecurityException("Pipe caller logon or enabled role differs from actual process token.");Check();
        }
        internal static HostedActor Capture(NamedPipeServerStream pipe)
        {
            FixedServiceIdentity.Require();uint pid=HostedPipe.ClientPid(pipe);string observed=null;Luid observedLogon=new Luid();bool observedAdmin=false;
            pipe.RunAsClient(delegate {using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                if(identity.ImpersonationLevel==TokenImpersonationLevel.Anonymous || identity.User==null) throw new SecurityException("Anonymous pipe identity refused.");
                observed=identity.User.Value;
                observedAdmin=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                uint length=(uint)Marshal.SizeOf(typeof(Statistics)),needed;IntPtr data=Marshal.AllocHGlobal((int)length);
                try {
                    if(!GetTokenInformation(identity.AccessToken,10,data,length,out needed) || needed>length) throw new Win32Exception(Marshal.GetLastWin32Error());
                    observedLogon=((Statistics)Marshal.PtrToStructure(data,typeof(Statistics))).AuthenticationId;
                } finally {Marshal.FreeHGlobal(data);}
            }});
            SafeWaitHandle process=OpenProcess(0x1000|0x100000,false,pid);if(process.IsInvalid) {int error=Marshal.GetLastWin32Error();process.Dispose();throw new Win32Exception(error);}
            SafeAccessTokenHandle token=null;
            try {
                if(!OpenProcessToken(process,0x000b,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
                HostedActor result=new HostedActor(pipe,process,token,observed,observedLogon,observedAdmin);if(HostedPipe.ClientPid(pipe)!=pid) throw new SecurityException("Original pipe process changed during identity capture.");return result;
            } catch {if(token!=null) token.Dispose();process.Dispose();throw;}
        }
        private IntPtr Information(int kind,int maximum)
        {
            uint count;GetTokenInformation(token,kind,IntPtr.Zero,0,out count);
            if(count<1 || count>maximum) throw new SecurityException("Actual Windows token field exceeds bound.");
            IntPtr value=Marshal.AllocHGlobal((int)count);
            if(!GetTokenInformation(token,kind,value,count,out count)) {Marshal.FreeHGlobal(value);throw new Win32Exception(Marshal.GetLastWin32Error());}return value;
        }
        private Statistics Stats() {IntPtr value=Information(10,256);try {return (Statistics)Marshal.PtrToStructure(value,typeof(Statistics));}finally {Marshal.FreeHGlobal(value);}}
        private uint Number(int kind) {IntPtr value=Information(kind,16);try{return (uint)Marshal.ReadInt32(value);}finally{Marshal.FreeHGlobal(value);}}
        private static bool Same(Luid a,Luid b) {return a.Low==b.Low && a.High==b.High;}
        private void Account(WindowsIdentity identity)
        {
            string[] account=identity.Name.Split('\\');
            if(account.Length!=2 || !String.Equals(account[0],Environment.MachineName,StringComparison.OrdinalIgnoreCase))
                throw new SecurityException("This commissioning profile requires an actual current local Windows account.");
            IntPtr buffer;uint status=NetUserGetInfo(null,account[1],1,out buffer);if(status!=0) throw new SecurityException("Current local Windows account unavailable: "+status);
            try {UserInfo info=(UserInfo)Marshal.PtrToStructure(buffer,typeof(UserInfo));
                if((info.Flags&(2U|0x10U|0x800000U))!=0) throw new SecurityException("Actual Windows account is disabled, locked or password-expired.");
            } finally {NetApiBufferFree(buffer);}
        }
        private void InteractiveSession()
        {
            if(Session==0) throw new SecurityException("Interactive nonservice client session required.");
            IntPtr buffer;uint bytes;
            if(!WTSQuerySessionInformation(IntPtr.Zero,Session,25,out buffer,out bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                // WTSINFOEX_LEVEL1 is the aligned union at offset8 on x64, the
                // only supported hosted build. Unknown/locked is a refusal.
                if(IntPtr.Size!=8 || bytes<20 || Marshal.ReadInt32(buffer)!=1 || (uint)Marshal.ReadInt32(buffer,8)!=Session ||
                    Marshal.ReadInt32(buffer,12)!=0 || Marshal.ReadInt32(buffer,16)!=1)
                    throw new SecurityException("Actual Windows interactive session is not active and unlocked.");
            } finally {WTSFreeMemory(buffer);}
        }
        internal void Check()
        {
            FixedServiceIdentity.Require();if(age.Elapsed.TotalSeconds>=1800 || !pipe.IsConnected || WaitForSingleObject(process,0)!=0x102)
                throw new SecurityException("Original Windows client process/pipe or finite session expired.");
            Statistics now=Stats();if(now.TokenType!=1 || !Same(now.TokenId,original.TokenId) || !Same(now.AuthenticationId,original.AuthenticationId) ||
                !Same(now.ModifiedId,original.ModifiedId) || Number(12)!=Session) throw new SecurityException("Original Windows primary token or logon generation changed.");
            using(WindowsIdentity identity=new WindowsIdentity(token.DangerousGetHandle())) {
                if(identity.User==null || identity.User.Value!=Sid || !identity.IsAuthenticated ||
                    !new WindowsPrincipal(identity).IsInRole(new SecurityIdentifier("S-1-5-4")) || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)!=Administrator)
                    throw new SecurityException("Current Windows principal or Admin role changed.");
                Account(identity);
            }
            InteractiveSession();
        }
        internal void RequireAdmin(string enrolledSid)
        {
            Check();if(!Administrator || (enrolledSid!=null && enrolledSid!=Sid)) throw new SecurityException("Actual enrolled first Admin is required for hosted deployment.");
        }
        public void Dispose() {token.Dispose();process.Dispose();}
    }
}
