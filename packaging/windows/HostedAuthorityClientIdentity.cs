using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Current local original client only, not product Admin/PAM/grant proof.
    internal sealed class HostedClientIdentity : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Luid {public uint Low;public int High;}
        [StructLayout(LayoutKind.Sequential)] private struct Statistics {
            public Luid Token,Logon;public long Expiration;public uint Type,Level,Charged,Available,Groups,Privileges;public Luid Modified;
        }
        [StructLayout(LayoutKind.Sequential)] private struct AccountInfo {public IntPtr Name,FullName,Comment;public uint Flags;public IntPtr Sid;}
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr data,uint length,out uint needed);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool LookupPrivilegeValue(string system,string name,out Luid value);
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] private static extern uint NetUserGetInfo(string server,string name,uint level,out IntPtr data);
        [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr data);
        [DllImport("wtsapi32.dll",SetLastError=true)] private static extern bool WTSQuerySessionInformation(IntPtr server,uint session,int kind,out IntPtr data,out uint bytes);
        [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr data);
        private readonly SafeAccessTokenHandle token;private readonly Statistics initial;private readonly uint session;
        internal readonly string Sid;
        internal SafeAccessTokenHandle Token {get{return token;}}
        internal HostedClientIdentity() {
            NoImpersonation();SafeAccessTokenHandle opened;
            if(!OpenProcessToken(new IntPtr(-1),8,out opened)) throw new Win32Exception(Marshal.GetLastWin32Error());token=opened;
            try {initial=Stats(token);session=Number(token,12);using(WindowsIdentity identity=new WindowsIdentity(token.DangerousGetHandle())) {
                if(identity.User==null || !identity.IsAuthenticated || !new WindowsPrincipal(identity).IsInRole(new SecurityIdentifier("S-1-5-4"))) throw new SecurityException("Actual authenticated interactive client required.");
                Sid=Wire.Sid(identity.User.Value);if(Sid=="S-1-5-18" || Sid=="S-1-5-19" || Sid=="S-1-5-20" || Sid.StartsWith("S-1-5-80-",StringComparison.Ordinal)) throw new SecurityException("Service identities cannot perform an original-client manual save.");
            }Check();}catch {token.Dispose();throw;}
        }
        private static bool Same(Luid left,Luid right) {return left.Low==right.Low && left.High==right.High;}
        private static void NoImpersonation() {
            SafeAccessTokenHandle thread;if(OpenThreadToken(new IntPtr(-2),8,true,out thread)) {thread.Dispose();throw new SecurityException("Manual client cannot run under impersonation.");}
            int error=Marshal.GetLastWin32Error();if(thread!=null) thread.Dispose();if(error!=1008) throw new Win32Exception(error);
        }
        private static IntPtr Info(SafeAccessTokenHandle selected,int kind,int maximum) {
            uint needed;GetTokenInformation(selected,kind,IntPtr.Zero,0,out needed);if(needed<1 || needed>maximum) throw new SecurityException("Original client token field exceeds bound.");
            IntPtr data=Marshal.AllocHGlobal((int)needed);uint allocated=needed;
            if(!GetTokenInformation(selected,kind,data,allocated,out needed) || needed>allocated) {int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(data);throw new Win32Exception(error);}return data;
        }
        private static Statistics Stats(SafeAccessTokenHandle selected) {IntPtr data=Info(selected,10,256);try {return (Statistics)Marshal.PtrToStructure(data,typeof(Statistics));}finally {Marshal.FreeHGlobal(data);}}
        private static uint Number(SafeAccessTokenHandle selected,int kind) {IntPtr data=Info(selected,kind,16);try {return unchecked((uint)Marshal.ReadInt32(data));}finally {Marshal.FreeHGlobal(data);}}
        internal byte[] Fingerprint() {
            Check();using(Wire.Writer writer=new Wire.Writer("luma-windows-manual-client-v1")) {writer.Text(Sid,184);writer.U32(session);
                foreach(Luid value in new Luid[]{initial.Token,initial.Logon,initial.Modified}) {writer.U32(value.Low);writer.U32(unchecked((uint)value.High));}return writer.Bytes();}
        }
        internal void Check() {
            NoImpersonation();SafeAccessTokenHandle live;if(!OpenProcessToken(new IntPtr(-1),8,out live)) throw new Win32Exception(Marshal.GetLastWin32Error());
            using(live) {
                Statistics now=Stats(live);if(now.Type!=1 || !Same(initial.Token,now.Token) || !Same(initial.Logon,now.Logon) || !Same(initial.Modified,now.Modified) || Number(live,12)!=session || session==0)
                    throw new SecurityException("Actual original process token, logon or session changed.");
                using(WindowsIdentity identity=new WindowsIdentity(live.DangerousGetHandle())) {
                    if(identity.User==null || identity.User.Value!=Sid || !identity.IsAuthenticated) throw new SecurityException("Original client identity changed.");
                    string[] name=identity.Name.Split('\\');if(name.Length!=2 || !String.Equals(name[0],Environment.MachineName,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("This profile requires a current local Windows account.");
                    IntPtr account;uint result=NetUserGetInfo(null,name[1],23,out account);if(result!=0) throw new SecurityException("Original local account is unavailable: "+result);
                    try {AccountInfo value=(AccountInfo)Marshal.PtrToStructure(account,typeof(AccountInfo));if(value.Sid==IntPtr.Zero || new SecurityIdentifier(value.Sid).Value!=Sid || (value.Flags&(2U|0x10U|0x800000U))!=0) throw new SecurityException("Original local account was replaced, disabled, locked or password-expired.");}finally {NetApiBufferFree(account);}
                }
                IntPtr privileges=Info(live,3,8192);try {
                    uint count=unchecked((uint)Marshal.ReadInt32(privileges));if(count>128) throw new SecurityException("Original privilege list exceeds bound.");
                    foreach(string name in new string[]{"SeBackupPrivilege","SeRestorePrivilege","SeDebugPrivilege","SeTakeOwnershipPrivilege","SeSecurityPrivilege"}) {
                        Luid blocked;if(!LookupPrivilegeValue(null,name,out blocked)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        for(int index=0;index<count;index++) {IntPtr entry=IntPtr.Add(privileges,4+index*12);if(unchecked((uint)Marshal.ReadInt32(entry))==blocked.Low && Marshal.ReadInt32(entry,4)==blocked.High && (Marshal.ReadInt32(entry,8)&2)!=0) throw new SecurityException("Manual save cannot use enabled ACL-bypass privileges.");}
                    }
                }finally {Marshal.FreeHGlobal(privileges);}
            }
            IntPtr state;uint bytes;if(!WTSQuerySessionInformation(IntPtr.Zero,session,25,out state,out bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {if(IntPtr.Size!=8 || bytes<20 || Marshal.ReadInt32(state)!=1 || unchecked((uint)Marshal.ReadInt32(state,8))!=session || Marshal.ReadInt32(state,12)!=0 || Marshal.ReadInt32(state,16)!=1) throw new SecurityException("Original interactive session is not active and unlocked.");}finally {WTSFreeMemory(state);}
        }
        public void Dispose() {token.Dispose();}
    }
}
