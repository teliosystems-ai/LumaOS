using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;
using Luma.Windows.Hosted;
using Luma.Windows;

// Pure provider-result and monotonic-cache tests, not a BitLocker fixture or
// enterprise authorization. Real observations run separately without changes.
public static class LumaHostedHostProtectionFixture
{
    private const string Volume=@"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";
    private const string Sid="S-1-5-21-1-2-3-1001";
    private static int assertions;
    private static void Require(bool value) {if(!value) throw new Exception("Host-protection assertion failed.");assertions++;}
    private static void Refuse(Action action) {try {action();}catch(SecurityException) {assertions++;return;}catch(InvalidDataException) {assertions++;return;}throw new Exception("Unsafe host protection admitted.");}
    private static Dictionary<string,object> Inputs()
    {return new Dictionary<string,object>(StringComparer.Ordinal) {{"protection_return",(uint)0},{"protection",(uint)1},{"conversion_return",(uint)0},{"conversion",(uint)1},{"percentage",(uint)100},{"encryption_return",(uint)0},{"encryption_method",(uint)6},{"lock_return",(uint)0},{"lock",(uint)0}};}
    private static HostManagementProtection Management(string sid,uint? domain,uint? aad,bool? mdm,string registry,Dictionary<string,uint> policies,bool subkeys)
    {return HostManagementProtection.Evaluate(sid,domain,aad,mdm,registry,policies,subkeys);}
    private static HostManagementProtection Local()
    {return Management(Sid,2,0,false,"observed",new Dictionary<string,uint>(),false);}
    private static HostProtectionObservation Good()
    {return new HostProtectionObservation(HostVolumeProtection.Evaluate(Volume,123,Inputs()),Local());}
    public static int Run()
    {
        assertions=0;Require(WindowsHostProtection.VolumeName(Volume));Require(!WindowsHostProtection.VolumeName(@"C:\"));Require(!WindowsHostProtection.VolumeName(Volume+"extra"));
        Good().RequireAdmitted(Volume,123,Sid);Require(true);
        Refuse(delegate {Good().RequireAdmitted(Volume,124,Sid);});Refuse(delegate {Good().RequireAdmitted(Volume,123,"S-1-5-21-1-2-3-1002");});
        Refuse(delegate {Good().RequireAdmitted(@"\\?\Volume{11234567-89ab-cdef-0123-456789abcdef}\",123,Sid);});
        Dictionary<string,object> reverse=new Dictionary<string,object>();List<string> keys=new List<string>(Inputs().Keys);keys.Reverse();foreach(string key in keys) reverse.Add(key,Inputs()[key]);Require(HostVolumeProtection.Evaluate(Volume,123,reverse).Protected);
        foreach(string key in Inputs().Keys) {
            Dictionary<string,object> invalid=Inputs();invalid.Remove(key);Require(!HostVolumeProtection.Evaluate(Volume,123,invalid).Protected);
            foreach(object bad in new object[]{null,true,1,"1",(ulong)1,-1,1.0}) {invalid=Inputs();invalid[key]=bad;Require(!HostVolumeProtection.Evaluate(Volume,123,invalid).Protected);}
        }
        foreach(string key in new string[]{"protection_return","conversion_return","encryption_return","lock_return"}) foreach(uint code in new uint[]{5,0x80070005,0x80041003,0x80041010,0x8004100e,123}) {
            Dictionary<string,object> invalid=Inputs();invalid[key]=code;HostVolumeProtection result=HostVolumeProtection.Evaluate(Volume,123,invalid);Require(!result.Protected && result.ErrorCode==code && result.Status==WindowsHostProtection.Failure(code));Refuse(result.RequireProtected);
        }
        foreach(uint conversion in new uint[]{0,2,3,4,5,6,UInt32.MaxValue}) {Dictionary<string,object> value=Inputs();value["conversion"]=conversion;Require(!HostVolumeProtection.Evaluate(Volume,123,value).Protected);}
        Dictionary<string,object> off=Inputs();off["protection"]=(uint)0;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="suspended-or-protection-off");
        off["conversion"]=(uint)0;off["encryption_method"]=(uint)0;off["percentage"]=(uint)0;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="fully-decrypted");
        off=Inputs();off["lock"]=(uint)1;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="locked");
        Require(HostVolumeProtection.Evaluate(Volume,123,new Dictionary<string,object>{{"lock_return",(uint)0},{"lock",(uint)1}}).Status=="locked");
        off=Inputs();off["protection_return"]=(uint)5;off["protection"]=null;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="query-access-denied");
        off=Inputs();off["protection"]=(uint)2;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="protection-unknown");
        foreach(uint method in new uint[]{1,2,3,4,5,6,7}) {off=Inputs();off["encryption_method"]=method;Require(HostVolumeProtection.Evaluate(Volume,123,off).Protected);}
        foreach(string key in new string[]{"percentage","lock","protection","encryption_method"}) {off=Inputs();off[key]=UInt32.MaxValue;Require(!HostVolumeProtection.Evaluate(Volume,123,off).Protected);}
        foreach(uint percentage in new uint[]{0,1,50,99}) {off=Inputs();off["percentage"]=percentage;Require(!HostVolumeProtection.Evaluate(Volume,123,off).Protected);}
        off=Inputs();off["protection"]=(uint)0;off["conversion"]=(uint)0;off["encryption_method"]=(uint)0;Require(HostVolumeProtection.Evaluate(Volume,123,off).Status=="invalid-provider-result");
        WindowsIdentity retained;string actual;
        using(WindowsIdentity original=WindowsIdentity.GetCurrent()) {actual=original.User.Value;retained=new WindowsIdentity(original.Token);}
        using(retained) {Require(retained.User.Value==actual);using(WindowsImpersonationContext context=retained.Impersonate()) using(WindowsIdentity current=WindowsIdentity.GetCurrent()) Require(current.User.Value==actual);}
        string nonce=new string('a',64),distribution="LumaHosted-"+new string('b',64)+"-1-"+new string('c',32);
        string[] arguments=HostedWslObserverContract.Arguments(distribution,nonce);Require(arguments.Length==3 && arguments[0]=="configuration-observer" && arguments[1]==distribution && arguments[2]==nonce);
        Refuse(delegate {HostedWslObserverContract.Arguments(distribution+" --exec shell",nonce);});Refuse(delegate {HostedWslObserverContract.Arguments(distribution,new string('0',64));});
        Require(HostedWslObserverContract.OwnedEnvironment(0,IntPtr.Zero,0));Require(HostedWslObserverContract.OwnedEnvironment(0,new IntPtr(1),128));
        Require(!HostedWslObserverContract.OwnedEnvironment(0,IntPtr.Zero,1));Require(!HostedWslObserverContract.OwnedEnvironment(0,new IntPtr(1),129));Require(!HostedWslObserverContract.OwnedEnvironment(unchecked((int)0x80070005),new IntPtr(1),UInt32.MaxValue));
        MethodInfo release=typeof(HostedWslObserverContract).GetMethod("ReleaseEnvironment",BindingFlags.Static|BindingFlags.NonPublic);
        release.Invoke(null,new object[]{unchecked((int)0x80070005),new IntPtr(1),UInt32.MaxValue});release.Invoke(null,new object[]{0,new IntPtr(1),(uint)129});Require(true);
        IntPtr empty=Marshal.AllocCoTaskMem(1);release.Invoke(null,new object[]{0,empty,(uint)0});Require(true);
        IntPtr array=Marshal.AllocCoTaskMem(IntPtr.Size*2);Marshal.WriteIntPtr(array,0,Marshal.StringToCoTaskMemAnsi("FIRST=fixture-data"));Marshal.WriteIntPtr(array,IntPtr.Size,Marshal.StringToCoTaskMemAnsi("SECOND=fixture-data"));release.Invoke(null,new object[]{0,array,(uint)2});Require(true);
        byte[] frame=HostedWslObserverContract.Encode(nonce,2,65534,0,128);HostedWslObserverContract.RequireClosed(frame,nonce);Require(true);
        foreach(byte[] invalid in new byte[][]{HostedWslObserverContract.Encode(nonce,1,65534,0,1),HostedWslObserverContract.Encode(nonce,2,0,0,1),HostedWslObserverContract.Encode(nonce,2,65534,7,1)}) Refuse(delegate {HostedWslObserverContract.RequireClosed(invalid,nonce);});
        Refuse(delegate {HostedWslObserverContract.RequireClosed(frame,new string('d',64));});Refuse(delegate {HostedWslObserverContract.Encode(nonce,2,65534,0,129);});
        byte[] trailing=new byte[frame.Length+1];Buffer.BlockCopy(frame,0,trailing,0,frame.Length);Refuse(delegate {HostedWslObserverContract.RequireClosed(trailing,nonce);});
        Local().RequireLocalChecks(Sid);Require(Local().KnownLocalChecksPassed);
        foreach(HostManagementProtection value in new HostManagementProtection[]{Management(Sid,null,0,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,null,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,0,null,"observed",new Dictionary<string,uint>(),false),Management(Sid,0,0,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,4,0,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,3,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,0,false,"unknown",new Dictionary<string,uint>(),false),Management(Sid,2,0,false,"observed",null,false),Management("S-1-5-18",2,0,false,"observed",new Dictionary<string,uint>(),false)}) {Require(!value.KnownLocalChecksPassed);Refuse(delegate {value.RequireLocalChecks(Sid);});}
        foreach(HostManagementProtection value in new HostManagementProtection[]{Management(Sid,3,0,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,1,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,2,false,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,0,true,"observed",new Dictionary<string,uint>(),false),Management(Sid,2,0,false,"observed",new Dictionary<string,uint>{{"AllowWSL",1}},false),Management(Sid,2,0,false,"observed",new Dictionary<string,uint>(),true)}) {Require(value.Status=="enterprise-review-required");Refuse(delegate {value.RequireLocalChecks(Sid);});}
        Require(Management(Sid,null,null,null,"unknown",new Dictionary<string,uint>{{"AllowWSL",0}},false).Status=="wsl-policy-denied");
        Require(!Management(Sid,2,0,false,"observed",new Dictionary<string,uint>{{"AllowWSL",2}},false).KnownLocalChecksPassed);
        Require(!Management(Sid,2,0,false,"observed",new Dictionary<string,uint>{{"FuturePolicy",1}},false).KnownLocalChecksPassed);
        long clock=0;int captures=0;HostProtectionObservation next=Good();bool fail=false;
        HostProtectionSamples cache=new HostProtectionSamples(delegate {captures++;if(fail) throw new SecurityException("Query failed.");return next;},delegate {return clock;});
        cache.Read(false).RequireAdmitted(Volume,123,Sid);Require(captures==1);clock=999;cache.Read(false);Require(captures==1);
        next=new HostProtectionObservation(HostVolumeProtection.Unknown(Volume,123,"suspended-or-protection-off",0),Local());clock=1000;Refuse(delegate {cache.Read(false).RequireAdmitted(Volume,123,Sid);});Require(captures==2);
        next=Good();cache.Read(true);Require(captures==3);next=new HostProtectionObservation(Good().Volume,Management(Sid,3,0,false,"observed",new Dictionary<string,uint>(),false));Refuse(delegate {cache.Read(true).RequireAdmitted(Volume,123,Sid);});
        next=Good();cache.Read(true);fail=true;Refuse(delegate {cache.Read(true);});Refuse(delegate {cache.Read(false);});fail=false;clock=999;Refuse(delegate {cache.Read(false);});
        clock=2000;HostProtectionSamples stale=new HostProtectionSamples(delegate {clock+=5000;return Good();},delegate {return clock;});Refuse(delegate {stale.Read(true);});
        return assertions;
    }
}
