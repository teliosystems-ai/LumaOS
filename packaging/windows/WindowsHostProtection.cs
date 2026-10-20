using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows
{
    // Read-only observations and pure evaluation, never enterprise approval,
    // a product principal, a protected reservation or an encryption operation.
    public sealed class HostVolumeProtection
    {
        public string Volume {get;private set;}
        public uint Serial {get;private set;}
        public string Status {get;private set;}
        public uint ErrorCode {get;private set;}
        public uint? Protection {get;private set;}
        public uint? Conversion {get;private set;}
        public uint? EncryptionMethod {get;private set;}
        public uint? Lock {get;private set;}
        public bool Protected {get{return Status=="protected";}}
        public static HostVolumeProtection Unknown(string volume,uint serial,string status,uint error)
        {return new HostVolumeProtection {Volume=volume,Serial=serial,Status=status,ErrorCode=error};}
        public static HostVolumeProtection Evaluate(string volume,uint serial,IDictionary<string,object> values)
        {
            string[] fields={"protection_return","protection","conversion_return","conversion","percentage","encryption_return","encryption_method","lock_return","lock"};
            HostVolumeProtection result=Unknown(volume,serial,"invalid-provider-result",0);
            if(WindowsHostProtection.VolumeName(volume) && values!=null && values.ContainsKey("lock_return") && values["lock_return"] is uint) {
                uint returned=(uint)values["lock_return"];
                if(returned!=0) return Unknown(volume,serial,WindowsHostProtection.Failure(returned),returned);
                if(values.ContainsKey("lock") && values["lock"] is uint && (uint)values["lock"]==1) {result.Lock=1;result.Status="locked";return result;}
            }
            if(!WindowsHostProtection.VolumeName(volume) || values==null || values.Count!=fields.Length) return result;
            foreach(string field in new string[]{"protection_return","conversion_return","encryption_return","lock_return"}) {
                if(!values.ContainsKey(field) || !(values[field] is uint)) return result;
                if((uint)values[field]!=0) return Unknown(volume,serial,WindowsHostProtection.Failure((uint)values[field]),(uint)values[field]);
            }
            foreach(string field in fields) if(!values.ContainsKey(field) || !(values[field] is uint)) return result;
            uint p=(uint)values["protection"],c=(uint)values["conversion"],e=(uint)values["encryption_method"],l=(uint)values["lock"];
            result.Protection=p;result.Conversion=c;result.EncryptionMethod=e;result.Lock=l;
            if(p>2 || c>5 || e>7 || l>1 || (uint)values["percentage"]>100) return result;
            if(c==1 && (uint)values["percentage"]!=100 || c==0 && (uint)values["percentage"]!=0) return result;
            if(l==1) result.Status="locked";
            else if(c==0 && e==0 && p==0) result.Status="fully-decrypted";
            else if(c==1 && p==0 && e!=0) result.Status="suspended-or-protection-off";
            else if(c>=2) result.Status="conversion-incomplete";
            else if(c==1 && p==1 && e!=0) result.Status="protected";
            else if(p==2) result.Status="protection-unknown";
            return result;
        }
        public void RequireProtected()
        {if(!Protected) throw new SecurityException("Private product storage protection refused: "+Status+"; observation is not an encryption or repair action.");}
    }

    public sealed class HostManagementProtection
    {
        public string ContextSid {get;private set;}
        public string Status {get;private set;}
        public uint? DomainJoin {get;private set;}
        public uint? AadJoin {get;private set;}
        public bool? MdmRegistered {get;private set;}
        public bool WslPolicyConfigured {get;private set;}
        public bool WslExplicitlyDenied {get;private set;}
        public bool KnownLocalChecksPassed {get{return Status=="no-management-signals-observed";}}
        public static HostManagementProtection Evaluate(string context,uint? domain,uint? aad,bool? mdm,string registryStatus,IDictionary<string,uint> policies,bool policySubkeys)
        {
            HostManagementProtection value=new HostManagementProtection {ContextSid=context,DomainJoin=domain,AadJoin=aad,MdmRegistered=mdm,Status="unknown",WslPolicyConfigured=policySubkeys || policies!=null && policies.Count!=0};
            uint allow;
            if(policies!=null && policies.TryGetValue("AllowWSL",out allow) && allow==0) {value.WslExplicitlyDenied=true;value.Status="wsl-policy-denied";return value;}
            if(context==null) return value;
            if(context=="S-1-5-18" || context=="S-1-5-19" || context=="S-1-5-20") {value.Status="non-user-token-context";return value;}
            if(registryStatus!="observed" || policies==null || domain==null || aad==null || mdm==null || domain<1 || domain>3 || aad>2) return value;
            foreach(KeyValuePair<string,uint> policy in policies) if(!WindowsHostProtection.PolicyName(policy.Key) || policy.Value>1) return value;
            if(domain==3 || aad!=0 || mdm.Value || value.WslPolicyConfigured) {value.Status="enterprise-review-required";return value;}
            value.Status="no-management-signals-observed";return value;
        }
        public void RequireLocalChecks(string sid)
        {
            if(!KnownLocalChecksPassed || ContextSid!=sid) throw new SecurityException("Windows policy admission refused: "+Status+". Managed, configured or unknown policy requires separate authenticated enterprise authorization; observations cannot provide it.");
        }
    }

    public sealed class HostProtectionObservation
    {
        public HostVolumeProtection Volume {get;private set;}
        public HostManagementProtection Management {get;private set;}
        public HostProtectionObservation(HostVolumeProtection volume,HostManagementProtection management)
        {if(volume==null || management==null) throw new ArgumentNullException("observation");Volume=volume;Management=management;}
        public void RequireAdmitted(string volume,uint serial,string callerSid)
        {
            Volume.RequireProtected();Management.RequireLocalChecks(callerSid);
            if(!String.Equals(Volume.Volume,volume,StringComparison.OrdinalIgnoreCase) || Volume.Serial!=serial) throw new SecurityException("Actual private backing volume changed after host protection admission.");
        }
    }

    // A bounded sample cache only. Production authority independently checks
    // the original actor, namespace, expected volume and actual observed state.
    public sealed class HostProtectionSamples
    {
        public const long ReuseMilliseconds=1000;
        private readonly Func<HostProtectionObservation> collect;private readonly Func<long> clock;
        private HostProtectionObservation sample;private long started;private long latest=-1;
        public HostProtectionSamples(Func<HostProtectionObservation> collect,Func<long> clock)
        {if(collect==null || clock==null) throw new ArgumentNullException("sample source");this.collect=collect;this.clock=clock;}
        public HostProtectionObservation Read(bool fresh)
        {
            long now=clock();if(now<0 || now<latest) {sample=null;throw new SecurityException("Host observation monotonic clock regressed.");}latest=now;
            if(!fresh && sample!=null && now-started<ReuseMilliseconds) return sample;
            sample=null;started=now;HostProtectionObservation next=collect();long end=clock();
            if(next==null || end<now || end-now>=WindowsHostProtection.MaximumObservationMilliseconds) throw new SecurityException("Host protection observation is missing, stale or exceeded its bounded sample window.");
            latest=end;sample=next;return next;
        }
    }

    public static class WindowsHostProtection
    {
        public const int MaximumObservationMilliseconds=5000;
        private static readonly object Gate=new object();private static Task<HostProtectionObservation> pending;
        private const string Namespace="root\\CIMV2\\Security\\MicrosoftVolumeEncryption";
        private const string PolicyPath="SOFTWARE\\Policies\\WSL";
        private static readonly HashSet<string> Policies=new HashSet<string>(StringComparer.Ordinal) {"AllowWSL","AllowInboxWSL","AllowWSL1","AllowDebugShell","AllowDiskMount","AllowKernelUserSetting","AllowSystemDistroUserSetting","AllowKernelCommandLineUserSetting","AllowNestedVirtualization","AllowKernelDebugUserSetting","AllowNetworkingModeUserSetting","AllowFirewallUserSetting","AllowWSLContainer","AllowWSLContainerPrivileged"};
        [StructLayout(LayoutKind.Sequential)] private struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information information);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder name,uint size,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle,StringBuilder name,uint size,out uint serial,out uint length,out uint flags,StringBuilder filesystem,uint filesystemSize);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] private static extern uint NetGetJoinInformation(string server,out IntPtr name,out uint status);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr value);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] private static extern int NetGetAadJoinInformation(string tenant,out IntPtr info);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("netapi32.dll")] private static extern void NetFreeAadJoinInformation(IntPtr info);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("mdmregistration.dll",CharSet=CharSet.Unicode)] private static extern int IsDeviceRegisteredWithManagement([MarshalAs(UnmanagedType.Bool)] out bool registered,uint length,IntPtr upn);
        public static bool VolumeName(string value) {return value!=null && Regex.IsMatch(value,@"\A\\\\\?\\Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\\\z",RegexOptions.CultureInvariant);}
        public static bool PolicyName(string value) {return value!=null && Policies.Contains(value);}
        public static string Failure(uint code)
        {
            if(code==5 || code==0x80070005 || code==0x80041003) return "query-access-denied";
            if(code==0x8004100e || code==0x80041010 || code==0x80041011 || code==0x80041013) return "provider-unavailable";
            return "query-failed";
        }
        private static uint Error(Exception error) {return unchecked((uint)Marshal.GetHRForException(error));}
        private static HostVolumeProtection Volume(string path)
        {
            List<SafeFileHandle> held=new List<SafeFileHandle>();string volume="";uint serial=0;
            try {
                if(path==null || !Regex.IsMatch(path,@"\A[A-Za-z]:\\",RegexOptions.CultureInvariant) || path.Contains("/") || !String.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Canonical existing local path required.");
                string root=Path.GetPathRoot(path),current=root;List<string> names=new List<string>();names.Add(root);
                foreach(string part in path.Substring(root.Length).TrimEnd('\\').Split('\\')) if(part.Length!=0) {current=Path.Combine(current,part);names.Add(current);}
                foreach(string name in names) {
                    SafeFileHandle handle=CreateFile(name,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(handle.IsInvalid) {int code=Marshal.GetLastWin32Error();handle.Dispose();return HostVolumeProtection.Unknown(volume,serial,Failure((uint)code),(uint)code);}held.Add(handle);
                    Information info;if(!GetFileInformationByHandle(handle,out info)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    if((info.Attributes&0x10)==0 || (info.Attributes&(0x400|0x1000|0x40000|0x400000))!=0) throw new SecurityException("Storage observation refuses linked, cloud or non-directory input.");
                }
                SafeFileHandle target=held[held.Count-1];Information before;if(!GetFileInformationByHandle(target,out before)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                StringBuilder final=new StringBuilder(32768),label=new StringBuilder(261),fs=new StringBuilder(261);uint maximum,flags;
                uint size=GetFinalPathNameByHandle(target,final,(uint)final.Capacity,1);if(size==0 || size>=final.Capacity) throw new SecurityException("Actual held volume name unavailable.");
                string resolved=final.ToString();int end=resolved.IndexOf("}\\",StringComparison.Ordinal);if(end<0) throw new SecurityException("Actual held volume GUID unavailable.");volume=resolved.Substring(0,end+2);if(!VolumeName(volume)) throw new SecurityException("Actual held volume GUID is malformed.");
                if(!GetVolumeInformationByHandleW(target,label,(uint)label.Capacity,out serial,out maximum,out flags,fs,(uint)fs.Capacity)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                if(fs.ToString()!="NTFS" || before.Volume!=serial) return HostVolumeProtection.Unknown(volume,serial,"unsupported-filesystem",0);
                HostVolumeProtection result=QueryVolume(volume,serial);
                Information after;if(!GetFileInformationByHandle(target,out after) || before.Volume!=after.Volume || before.IndexHigh!=after.IndexHigh || before.IndexLow!=after.IndexLow || before.Attributes!=after.Attributes) return HostVolumeProtection.Unknown(volume,serial,"backing-volume-changed",0);
                final.Length=0;size=GetFinalPathNameByHandle(target,final,(uint)final.Capacity,1);if(size==0 || size>=final.Capacity || !String.Equals(final.ToString(),resolved,StringComparison.OrdinalIgnoreCase)) return HostVolumeProtection.Unknown(volume,serial,"backing-volume-changed",0);
                return result;
            } catch(Exception error) {
                if(error is OutOfMemoryException || error is AccessViolationException) throw;
                uint code=Error(error);return HostVolumeProtection.Unknown(volume,serial,error is SecurityException?"invalid-storage-path":Failure(code),code);
            } finally {foreach(SafeFileHandle handle in held) handle.Dispose();}
        }
        private static void Method(ManagementObject volume,string name,IDictionary<string,object> values,string result,string[] outputs)
        {
            using(ManagementBaseObject input=volume.GetMethodParameters(name)) {
                if(name=="GetConversionStatus") input["PrecisionFactor"]=(uint)0;
                using(ManagementBaseObject output=volume.InvokeMethod(name,input,new InvokeMethodOptions {Timeout=TimeSpan.FromSeconds(2)})) {
                    values.Add(result,output["ReturnValue"]);foreach(string field in outputs) {string[] pair=field.Split(':');values.Add(pair[0],output[pair[1]]);}
                }
            }
        }
        private static HostVolumeProtection QueryVolume(string volume,uint serial)
        {
            ManagementScope scope=new ManagementScope("\\\\.\\"+Namespace,new ConnectionOptions {EnablePrivileges=false,Impersonation=ImpersonationLevel.Impersonate,Timeout=TimeSpan.FromSeconds(2)});
            using(ManagementObjectSearcher query=new ManagementObjectSearcher(scope,new ObjectQuery("SELECT DeviceID FROM Win32_EncryptableVolume"),new EnumerationOptions {ReturnImmediately=false,Rewindable=false,Timeout=TimeSpan.FromSeconds(2)}))
            using(ManagementObjectCollection objects=query.Get()) {
                ManagementObject selected=null;int count=0;
                try {
                    foreach(ManagementObject item in objects) {
                        count++;if(count>64) {item.Dispose();throw new SecurityException("Encryptable-volume inventory exceeds bound.");}
                        if(item["DeviceID"] is string && String.Equals((string)item["DeviceID"],volume,StringComparison.OrdinalIgnoreCase)) {if(selected!=null) {item.Dispose();throw new SecurityException("Duplicate encryptable-volume identity.");}selected=item;}else item.Dispose();
                    }
                    if(selected==null) return HostVolumeProtection.Unknown(volume,serial,"volume-not-exposed-by-provider",0);
                    Dictionary<string,object> values=new Dictionary<string,object>(StringComparer.Ordinal);
                    Method(selected,"GetLockStatus",values,"lock_return",new string[]{"lock:LockStatus"});
                    if(values["lock_return"] is uint && ((uint)values["lock_return"]!=0 || values["lock"] is uint && (uint)values["lock"]==1)) return HostVolumeProtection.Evaluate(volume,serial,values);
                    Method(selected,"GetProtectionStatus",values,"protection_return",new string[]{"protection:ProtectionStatus"});
                    Method(selected,"GetConversionStatus",values,"conversion_return",new string[]{"conversion:ConversionStatus","percentage:EncryptionPercentage"});
                    Method(selected,"GetEncryptionMethod",values,"encryption_return",new string[]{"encryption_method:EncryptionMethod"});
                    return HostVolumeProtection.Evaluate(volume,serial,values);
                } finally {if(selected!=null) selected.Dispose();}
            }
        }
        private static HostManagementProtection Management(WindowsIdentity caller)
        {
            uint? domain=null,aad=null;bool? mdm=null;IntPtr name=IntPtr.Zero,info=IntPtr.Zero;string registry="unknown";bool subkeys=false;
            Dictionary<string,uint> policies=new Dictionary<string,uint>(StringComparer.Ordinal);
            try {uint status;if(NetGetJoinInformation(null,out name,out status)==0) domain=status;} finally {if(name!=IntPtr.Zero) NetApiBufferFree(name);}
            try {bool registered;if(IsDeviceRegisteredWithManagement(out registered,0,IntPtr.Zero)==0) mdm=registered;}catch(DllNotFoundException) {}catch(EntryPointNotFoundException) {}
            try {using(WindowsImpersonationContext context=caller.Impersonate()) {if(NetGetAadJoinInformation(null,out info)==0) {
                if(info==IntPtr.Zero) aad=0;else {int observed=Marshal.ReadInt32(info);aad=observed==1 || observed==2?(uint)observed:UInt32.MaxValue;}
            }}} finally {if(info!=IntPtr.Zero) NetFreeAadJoinInformation(info);}
            try {
                using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) using(RegistryKey key=machine.OpenSubKey(PolicyPath,false)) {
                    registry="observed";
                    if(key!=null) {
                        string[] names=key.GetValueNames();if(names.Length>64 || key.SubKeyCount>16) throw new SecurityException("WSL policy inventory exceeds bound.");subkeys=key.SubKeyCount!=0;
                        foreach(string value in names) {
                            if(!PolicyName(value) || key.GetValueKind(value)!=RegistryValueKind.DWord || !(key.GetValue(value,null,RegistryValueOptions.DoNotExpandEnvironmentNames) is int)) throw new SecurityException("Unknown or malformed WSL policy.");
                            int current=(int)key.GetValue(value,null,RegistryValueOptions.DoNotExpandEnvironmentNames);if(current<0 || current>1) throw new SecurityException("Malformed WSL policy boolean.");policies.Add(value,(uint)current);
                        }
                    }
                }
            }catch(Exception error) {if(error is OutOfMemoryException || error is AccessViolationException) throw;registry="unknown";}
            return HostManagementProtection.Evaluate(caller.User==null?null:caller.User.Value,domain,aad,mdm,registry,policies,subkeys);
        }
        public static HostProtectionObservation Observe(string existingPath) {return Observe(existingPath,IntPtr.Zero);}
        public static HostProtectionObservation Observe(string existingPath,IntPtr callerToken)
        {return ObserveInternal(existingPath,callerToken,false);}
        public static HostVolumeProtection ObserveVolume(string existingPath)
        {return ObserveInternal(existingPath,IntPtr.Zero,true).Volume;}
        private static HostProtectionObservation ObserveInternal(string existingPath,IntPtr callerToken,bool volumeOnly)
        {
            Task<HostProtectionObservation> work;
            lock(Gate) {
                if(pending!=null && !pending.IsCompleted) return Failed("query-busy");
                WindowsIdentity caller=callerToken==IntPtr.Zero?WindowsIdentity.GetCurrent():new WindowsIdentity(callerToken);
                try {pending=Task.Factory.StartNew(delegate {using(caller) {HostVolumeProtection volume=Volume(existingPath);HostManagementProtection management;
                    try {management=volumeOnly?HostManagementProtection.Evaluate(null,null,null,null,"unknown",null,false):Management(caller);}catch(Exception error) {if(error is OutOfMemoryException || error is AccessViolationException) throw;management=HostManagementProtection.Evaluate(caller.User==null?null:caller.User.Value,null,null,null,"unknown",null,false);}return new HostProtectionObservation(volume,management);}});}
                catch {caller.Dispose();throw;}work=pending;
            }
            try {if(!work.Wait(MaximumObservationMilliseconds-100)) return Failed("query-timed-out");return work.GetAwaiter().GetResult();}
            catch(AggregateException) {return Failed("query-failed");}
        }
        private static HostProtectionObservation Failed(string status)
        {return new HostProtectionObservation(HostVolumeProtection.Unknown("",0,status,0),HostManagementProtection.Evaluate(null,null,null,null,"unknown",null,false));}
    }
}
