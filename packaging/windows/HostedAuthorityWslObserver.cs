using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Luma.Windows.Hosted
{
    internal sealed class PinnedConfigurationObserver : IDisposable
    {
        private readonly InstalledInputLease held;
        internal string Path {get;private set;}
        internal PinnedConfigurationObserver(AuthorityIdentity identity)
        {
            FixedServiceIdentity.Require();if(identity==null || identity.Domain!="host-deployment") throw new SecurityException("Authenticated host-deployment runtime identity required.");
            Path=HostedRuntimeFiles.Running;held=InstalledInputLease.Acquire(Path);
            try {if(held.Length<64 || held.Length>128*1024*1024) throw new SecurityException("Configuration observer executable exceeds runtime bounds.");
                string sha;using(SHA256 hash=SHA256.Create()) sha=Wire.Hex(hash.ComputeHash(held.Rewind()));
                if(sha!=identity.ServiceSha256) throw new SecurityException("Configuration observer is not the exact currently authenticated runtime executable.");Check();
            }catch {held.Dispose();throw;}
        }
        internal void Check() {FixedServiceIdentity.Require();held.Check();}
        public void Dispose() {held.Dispose();}
    }

    // Closed metadata only. A successful frame is not service health, Linux
    // authentication or product authority. Environment text never leaves child.
    public static class HostedWslObserverContract
    {
        public static string[] Arguments(string distribution,string nonce)
        {
            if(distribution==null || !Regex.IsMatch(distribution,@"\ALumaHosted-[0-9a-f]{64}-[1-9][0-9]{0,15}-[0-9a-f]{32}\z",RegexOptions.CultureInvariant)) throw new SecurityException("Exact owned distribution required.");
            Wire.Bytes(nonce,32,true);return new string[]{"configuration-observer",distribution,nonce};
        }
        public static bool OwnedEnvironment(int result,IntPtr environment,uint count)
        {return result==0 && count<=128 && (count==0 || environment!=IntPtr.Zero);}
        internal static void ReleaseEnvironment(int result,IntPtr environment,uint count)
        {
            // Failure outs have no ownership guarantee. Oversized successful
            // results are left exclusively to disposable-process teardown.
            if(!OwnedEnvironment(result,environment,count) || environment==IntPtr.Zero) return;
            try {for(uint index=0;index<count;index++) {IntPtr value=Marshal.ReadIntPtr(environment,checked((int)index*IntPtr.Size));if(value!=IntPtr.Zero) Marshal.FreeCoTaskMem(value);}}
            finally {Marshal.FreeCoTaskMem(environment);}
        }
        public static byte[] Encode(string nonce,uint version,uint uid,uint flags,uint count)
        {
            Wire.Bytes(nonce,32,true);if(count>128) throw new SecurityException("WSL configuration metadata exceeds supported inventory.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-wsl-configuration-v1")) {writer.Fixed(Wire.Bytes(nonce,32,true),32);writer.U32(version);writer.U32(uid);writer.U32(flags);writer.U32(count);return writer.Bytes();}
        }
        public static void RequireClosed(byte[] frame,string nonce)
        {
            Wire.Bytes(nonce,32,true);
            using(Wire.Reader reader=new Wire.Reader(Wire.Copy(frame,1,256),"luma-windows-wsl-configuration-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=nonce || reader.U32()!=2 || reader.U32()!=65534 || reader.U32()!=0 || reader.U32()>128) throw new SecurityException("Actual owned WSL slot is not version2/defaultnobody/zero interop-path-drive flags.");reader.End();
            }
        }
    }

    internal static class HostedWslConfigurationObserver
    {
        [DllImport("api-ms-win-wsl-api-l1-1-0.dll",CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool WslIsDistributionRegistered(string distribution);
        [DllImport("api-ms-win-wsl-api-l1-1-0.dll",CharSet=CharSet.Unicode)] private static extern int WslGetDistributionConfiguration(string distribution,out uint version,out uint uid,out uint flags,out IntPtr environment,out uint count);
        internal static int Child(string[] arguments)
        {
            if(arguments==null || arguments.Length!=3 || arguments[0]!="configuration-observer" || !Console.IsInputRedirected || !Console.IsOutputRedirected) throw new SecurityException("Read-only configuration helper requires its closed redirected invocation.");
            HostedWslObserverContract.Arguments(arguments[1],arguments[2]);
            using(WindowsIdentity caller=WindowsIdentity.GetCurrent()) if(caller.User==null || caller.User.Value=="S-1-5-18" || new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator)) throw new SecurityException("Configuration helper requires its actual nonprivileged original-user process.");
            if(!WslIsDistributionRegistered(arguments[1])) throw new SecurityException("Exact installation-owned WSL slot is absent.");
            uint version=0,uid=0,flags=0,count=0;IntPtr environment=IntPtr.Zero;
            int result=WslGetDistributionConfiguration(arguments[1],out version,out uid,out flags,out environment,out count);
            if(result!=0) throw new SecurityException("WSL configuration API refused; failed-call output ownership is undefined and process teardown performs cleanup.");
            try {
                if(!HostedWslObserverContract.OwnedEnvironment(result,environment,count)) throw new SecurityException("WSL configuration failed or exceeded the supported allocation shape; child teardown retains all cleanup ownership.");
                byte[] frame=HostedWslObserverContract.Encode(arguments[2],version,uid,flags,count);using(Stream output=Console.OpenStandardOutput()) {output.Write(frame,0,frame.Length);output.Flush();}return 0;
            }finally {HostedWslObserverContract.ReleaseEnvironment(result,environment,count);}
        }
        internal static void RequireClosed(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,Action original)
        {
            Stopwatch deadline=Stopwatch.StartNew();string distribution=HostedGuestRunner.Distribution(identity,admission),nonce=Wire.Hex(Wire.Random(32));
            Action check=delegate {original();actor.RequireAdmin(identity.FirstAdminSid);if(deadline.ElapsedMilliseconds>=4000) throw new IOException("Read-only WSL observer exhausted its original four-second execution/five-second cleanup budget.");};
            check();using(PinnedConfigurationObserver binary=new PinnedConfigurationObserver(identity)) {
                using(OwnedWindowsProcess child=OwnedWindowsProcess.StartConfigurationObserver(binary,actor,distribution,nonce,check,deadline)) {
                    child.Input.Close();byte[] frame=GuestComputeFrames.BoundedEnd(child.Output,256,check,deadline,TimeSpan.FromSeconds(4));
                    child.RequireSuccess(check,TimeSpan.FromMilliseconds(Math.Max(1,4000-deadline.ElapsedMilliseconds)));
                    GuestComputeFrames.BoundedEnd(child.Error,1024,check,deadline,TimeSpan.FromSeconds(4));
                    if(!child.Exited) throw new SecurityException("Configuration observer original exit unobserved.");HostedWslObserverContract.RequireClosed(frame,nonce);binary.Check();check();
                }
            }
            check();
        }
    }
}
