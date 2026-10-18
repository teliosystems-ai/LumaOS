using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Luma.Windows.Hosted
{
    internal static class FixedServiceIdentity
    {
        internal const string Name="LumaHostedAuthority";
        [StructLayout(LayoutKind.Sequential)] private struct Status {public uint Type,State,Controls,Win32,Service,Checkpoint,Hint,Pid,Flags;}
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool QueryServiceStatusEx(IntPtr service,int kind,out Status status,int bytes,out int needed);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool CheckTokenMembership(IntPtr token,byte[] sid,out bool member);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll")] private static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        internal static SecurityIdentifier Require()
        {
            IntPtr token;
            if(OpenThreadToken(GetCurrentThread(),8,true,out token)) {CloseHandle(token);throw new SecurityException("Custody cannot run under client impersonation.");}
            if(Marshal.GetLastWin32Error()!=1008) throw new Win32Exception(Marshal.GetLastWin32Error());
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent())
                if(identity.User==null || identity.User.Value!="S-1-5-18") throw new SecurityException("Actual LocalSystem service required.");
            SecurityIdentifier sid=(SecurityIdentifier)new NTAccount("NT SERVICE",Name).Translate(typeof(SecurityIdentifier));
            byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);bool member;
            if(!CheckTokenMembership(IntPtr.Zero,bytes,out member)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(!member) throw new SecurityException("Actual fixed hosted-authority service SID is missing.");
            IntPtr manager=IntPtr.Zero,service=IntPtr.Zero;
            try {
                manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                service=OpenService(manager,Name,4);if(service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                Status status;int needed;
                if(!QueryServiceStatusEx(service,0,out status,Marshal.SizeOf(typeof(Status)),out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(needed>Marshal.SizeOf(typeof(Status)) || status.Type!=0x10 || status.State!=4 || status.Pid!=GetCurrentProcessId())
                    throw new SecurityException("SCM does not identify this fixed running own-process service.");
            } finally {if(service!=IntPtr.Zero) CloseServiceHandle(service);if(manager!=IntPtr.Zero) CloseServiceHandle(manager);}
            return sid;
        }
    }

    internal sealed class HardwareKey : IDisposable
    {
        private const string Provider="Microsoft Platform Crypto Provider";
        private IntPtr provider,key;
        private readonly string domain,installation;
        private byte[] publicBlob;
        internal byte[] PublicBlob {get{return (byte[])publicBlob.Clone();}}
        internal string KeyName {get{return "LumaOS.HostedAuthority.v1."+(domain=="host-deployment"?"host":"content")+"."+installation+".signing";}}
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptOpenStorageProvider(out IntPtr provider,string name,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptOpenKey(IntPtr provider,out IntPtr key,string name,uint legacy,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptCreatePersistedKey(IntPtr provider,out IntPtr key,string algorithm,string name,uint legacy,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptSetProperty(IntPtr value,string name,byte[] input,uint count,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptGetProperty(IntPtr value,string name,byte[] output,uint maximum,out uint count,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptFinalizeKey(IntPtr key,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptExportKey(IntPtr key,IntPtr export,string kind,IntPtr parameters,byte[] output,uint maximum,out uint count,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptSignHash(IntPtr key,IntPtr padding,byte[] hash,uint count,byte[] output,uint maximum,out uint written,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptFreeObject(IntPtr value);
        private HardwareKey(string domain,string installation) {PlatformCustodyProtocol.Index(domain);Wire.Bytes(installation,32,true);this.domain=domain;this.installation=installation;}
        private static void Success(int result,string operation) {if(result!=0) throw new CryptographicException(operation+": 0x"+((uint)result).ToString("x8"));}
        private byte[] Property(IntPtr handle,string name,int maximum,uint flags)
        {
            byte[] bytes=new byte[maximum];uint count;Success(NCryptGetProperty(handle,name,bytes,(uint)bytes.Length,out count,flags),"Read fixed hardware property");
            if(count<1 || count>maximum) throw new SecurityException("Hardware property exceeds exact bound.");Array.Resize(ref bytes,(int)count);return bytes;
        }
        private uint Number(IntPtr handle,string name) {byte[] value=Property(handle,name,4,0);if(value.Length!=4) throw new SecurityException("Hardware property must be DWORD.");return BitConverter.ToUInt32(value,0);}
        private string Text(string name)
        {
            byte[] value=Property(key,name,512,0);if(value.Length<2 || value.Length%2!=0 || value[value.Length-1]!=0 || value[value.Length-2]!=0) throw new SecurityException("Hardware text property is not exact UTF16.");
            string result=new UnicodeEncoding(false,false,true).GetString(value,0,value.Length-2);if(result.IndexOf('\0')>=0) throw new SecurityException("Hardware property hidden suffix.");return result;
        }
        private void Set(string name,uint value) {byte[] bytes=BitConverter.GetBytes(value);Success(NCryptSetProperty(key,name,bytes,4,0),"Set fixed hardware property");}
        private void Check(byte[] expected)
        {
            SecurityIdentifier service=FixedServiceIdentity.Require();
            PlatformCustodyProtocol.CheckKeyPolicy(Number(provider,"Impl Type"),Text("Algorithm Name"),Number(key,"Length"),
                Number(key,"Key Type"),Number(key,"Key Usage"),Number(key,"Export Policy"),Text("Name"),KeyName);
            if(Number(provider,"Security Descr Support")!=1) throw new SecurityException("Hardware provider cannot prove its DACL.");
            PlatformCustodyProtocol.CheckKeySecurity(Property(key,"Security Descr",65536,5),service.Value);
            byte[] blob=new byte[72];uint count;Success(NCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",IntPtr.Zero,blob,72,out count,0),"Read hardware public key");
            if(count!=72 || (expected!=null && !Wire.Equal(blob,expected))) throw new SecurityException("Actual hardware key identity differs.");publicBlob=blob;
        }
        internal static HardwareKey Create(string domain,string installation)
        {
            SecurityIdentifier service=FixedServiceIdentity.Require();HardwareKey result=new HardwareKey(domain,installation);
            try {
                Success(NCryptOpenStorageProvider(out result.provider,Provider,0),"Open fixed hardware provider");
                // Deliberately no overwrite flag, software provider or empty name.
                Success(NCryptCreatePersistedKey(result.provider,out result.key,"ECDSA_P256",result.KeyName,0,0x20|0x40),"Create new named TPM machine key");
                result.Set("Length",256);result.Set("Key Usage",2);result.Set("Export Policy",0);
                RawSecurityDescriptor descriptor=new RawSecurityDescriptor("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;"+service.Value+")");
                byte[] security=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(security,0);
                Success(NCryptSetProperty(result.key,"Security Descr",security,(uint)security.Length,5),"Set fixed key System/service DACL");
                Success(NCryptFinalizeKey(result.key,0x40),"Finalize TPM machine key");result.Check(null);return result;
            } catch {result.Dispose();throw;}
        }
        internal static HardwareKey Open(AuthorityIdentity identity)
        {
            FixedServiceIdentity.Require();HardwareKey result=new HardwareKey(identity.Domain,identity.Installation);
            try {Success(NCryptOpenStorageProvider(out result.provider,Provider,0),"Open fixed hardware provider");
                Success(NCryptOpenKey(result.provider,out result.key,result.KeyName,0,0x20|0x40),"Open commissioned TPM machine key");result.Check(identity.AuthorityKey);return result;
            } catch {result.Dispose();throw;}
        }
        internal static HardwareKey ResumePending(string domain,string installation)
        {
            // Only the coordinator calls this after reading an exact protected
            // commission.intent. It cannot select an arbitrary CNG key name.
            FixedServiceIdentity.Require();HardwareKey result=new HardwareKey(domain,installation);
            try {
                Success(NCryptOpenStorageProvider(out result.provider,Provider,0),"Open fixed hardware provider");
                int status=NCryptOpenKey(result.provider,out result.key,result.KeyName,0,0x20|0x40);
                if(unchecked((uint)status)==0x80090016U) {result.Dispose();return Create(domain,installation);}
                Success(status,"Resume exact pending machine key");result.Check(null);return result;
            } catch {result.Dispose();throw;}
        }
        internal byte[] Sign(byte[] input)
        {
            if(key==IntPtr.Zero) throw new ObjectDisposedException("HardwareKey");Wire.Copy(input,1,8192);Check(publicBlob);
            byte[] digest=Wire.HashBytes(input),signature=new byte[64];uint count;
            Success(NCryptSignHash(key,IntPtr.Zero,digest,32,signature,64,out count,0x40),"Sign exact hosted custody operation");
            if(count!=64 || !PlatformSignature.Verify(publicBlob,input,signature)) throw new SecurityException("Actual hardware signature verification failed.");Check(publicBlob);return signature;
        }
        public void Dispose() {if(key!=IntPtr.Zero){NCryptFreeObject(key);key=IntPtr.Zero;}if(provider!=IntPtr.Zero){NCryptFreeObject(provider);provider=IntPtr.Zero;}}
    }

    // Exact TPM2 encodings, also exercised without TBS by protocol tests. Policy
    // Signed authorizes the nonce-bound cpHash of one fixed NV_Extend only.
    public static class TpmWriteProtocol
    {
        public const uint Extend=0x136;
        private static byte[] U16(ushort n) {unchecked{return new byte[]{(byte)(n>>8),(byte)n};}}
        private static byte[] U32(uint n) {unchecked{return new byte[]{(byte)(n>>24),(byte)(n>>16),(byte)(n>>8),(byte)n};}}
        private static byte[] Two(byte[] value) {if(value==null || value.Length>4096) throw new InvalidDataException("TPM2B exceeds bound.");return Wire.Join(U16((ushort)value.Length),value);}
        internal static byte[] Request(ushort tag,uint code,params byte[][] body) {byte[] bytes=Wire.Join(body);return Wire.Join(U16(tag),U32((uint)bytes.Length+10),U32(code),bytes);}
        public static byte[] ExternalPublic(byte[] blob)
        {
            byte[] value=AuthorityIdentity.Public(blob),x=new byte[32],y=new byte[32];Buffer.BlockCopy(value,8,x,0,32);Buffer.BlockCopy(value,40,y,0,32);
            return Wire.Join(U16(0x23),U16(0x0b),U32(0x40040),U16(0),U16(0x10),U16(0x18),U16(0x0b),U16(3),U16(0x10),Two(x),Two(y));
        }
        public static byte[] KeyName(byte[] blob) {return Wire.Join(U16(0x0b),Wire.HashBytes(ExternalPublic(blob)));}
        public static byte[] PolicyReference(string domain,string installation)
        {
            PlatformCustodyProtocol.Index(domain);Wire.Bytes(installation,32,true);
            return Wire.Join(new byte[]{1},Wire.HashBytes(Encoding.ASCII.GetBytes("luma-windows-hosted-nv-policy-v1\n"+domain+"\n"+installation+"\n")));
        }
        public static byte[] Policy(byte[] blob,string domain,string installation)
        {
            byte[] signed=Wire.HashBytes(Wire.Join(new byte[32],U32(0x160),KeyName(blob)));
            byte[] reference=Wire.HashBytes(Wire.Join(signed,PolicyReference(domain,installation)));
            return Wire.HashBytes(Wire.Join(reference,U32(0x16c),U32(Extend)));
        }
        public static byte[] NvPublic(byte[] blob,string domain,string installation,bool written)
        {
            return Wire.Join(U32(PlatformCustodyProtocol.Index(domain)),U16(0x0b),U32(written?0x22040048U:0x02040048U),Two(Policy(blob,domain,installation)),U16(32));
        }
        public static byte[] NvName(byte[] blob,string domain,string installation,bool written) {return Wire.Join(U16(0x0b),Wire.HashBytes(NvPublic(blob,domain,installation,written)));}
        public static byte[] ExtendCpHash(byte[] blob,string domain,string installation,bool written,byte[] recordDigest)
        {
            byte[] name=NvName(blob,domain,installation,written);return Wire.HashBytes(Wire.Join(U32(Extend),name,name,Two(Wire.Copy(recordDigest,32,32))));
        }
        public static byte[] AuthorizationInput(byte[] nonce,byte[] cpHash,byte[] policyReference)
        {return Wire.Join(Wire.Copy(nonce,16,32),U32(5),Wire.Copy(cpHash,32,32),Wire.Copy(policyReference,33,33));}
        public static byte[] Start(byte[] nonce)
        {return Request(0x8001,0x176,U32(0x40000007),U32(0x40000007),Two(Wire.Copy(nonce,32,32)),U16(0),new byte[]{1},U16(0x10),U16(0x0b));}
        public static byte[] Load(byte[] publicBlob) {return Request(0x8001,0x167,U16(0),Two(ExternalPublic(publicBlob)),U32(0x40000007));}
        public static byte[] Signed(uint key,uint session,byte[] nonce,byte[] cpHash,byte[] policyReference,byte[] signature)
        {
            Handle(key,0x80);Handle(session,0x03);byte[] sig=Wire.Copy(signature,64,64),r=new byte[32],s=new byte[32];
            Buffer.BlockCopy(sig,0,r,0,32);Buffer.BlockCopy(sig,32,s,0,32);
            return Request(0x8001,0x160,U32(key),U32(session),Two(Wire.Copy(nonce,16,32)),Two(Wire.Copy(cpHash,32,32)),
                Two(Wire.Copy(policyReference,33,33)),U32(5),U16(0x18),U16(0x0b),Two(r),Two(s));
        }
        public static byte[] Restrict(uint session) {Handle(session,0x03);return Request(0x8001,0x16c,U32(session),U32(Extend));}
        public static byte[] Digest(uint session) {Handle(session,0x03);return Request(0x8001,0x189,U32(session));}
        public static byte[] Apply(string domain,uint session,byte[] recordDigest)
        {
            Handle(session,0x03);uint index=PlatformCustodyProtocol.Index(domain);
            return Request(0x8002,Extend,U32(index),U32(index),U32(9),U32(session),U16(0),new byte[]{0},U16(0),Two(Wire.Copy(recordDigest,32,32)));
        }
        public static byte[] Define(byte[] blob,string domain,string installation,byte[] ownerAuth)
        {
            byte[] auth=Wire.Copy(ownerAuth,1,64),session=null,encoded=null;
            try {encoded=Two(auth);session=Wire.Join(U32(0x40000009),U16(0),new byte[]{1},encoded);
                return Request(0x8002,0x12a,U32(0x40000001),U32((uint)session.Length),session,U16(0),Two(NvPublic(blob,domain,installation,false)));
            } finally {Array.Clear(auth,0,auth.Length);if(session!=null) Array.Clear(session,0,session.Length);if(encoded!=null) Array.Clear(encoded,0,encoded.Length);}
        }
        public static byte[] Flush(uint handle) {byte type=(byte)(handle>>24);if(type!=0x80 && type!=3) throw new SecurityException("Only owned transient/session handles can be flushed.");return Request(0x8001,0x165,U32(handle));}
        private static void Handle(uint value,byte kind) {if((value>>24)!=kind) throw new SecurityException("Unexpected TPM handle class.");}
        internal sealed class Response
        {
            private readonly byte[] bytes;private int at;
            internal Response(byte[] value,ushort tag)
            {
                bytes=Wire.Copy(value,10,4096);ushort actual=U16();uint length=U32(),result=U32();
                if(length!=bytes.Length || actual!=tag || result!=0) throw new SecurityException("Exact TPM command refused or response framing differs: 0x"+result.ToString("x8"));
            }
            internal byte[] Read(int count) {if(count<0 || count>bytes.Length-at) throw new InvalidDataException("Truncated TPM response.");byte[] result=new byte[count];Buffer.BlockCopy(bytes,at,result,0,count);at+=count;return result;}
            internal byte U8() {return Read(1)[0];}
            internal ushort U16() {return (ushort)(((uint)U8()<<8)|U8());}
            internal uint U32() {return ((uint)U16()<<16)|U16();}
            internal ulong U64() {return ((ulong)U32()<<32)|U32();}
            internal byte[] Two(int minimum,int maximum) {int count=U16();if(count<minimum || count>maximum) throw new InvalidDataException("TPM2B response length differs.");return Read(count);}
            internal void End() {if(at!=bytes.Length) throw new InvalidDataException("Trailing TPM response.");}
        }
    }

    internal sealed class FixedNvAuthority : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Parameters {public uint Version,Flags;}
        [DllImport("tbs.dll")] private static extern uint Tbsi_Context_Create(ref Parameters parameters,out IntPtr context);
        [DllImport("tbs.dll")] private static extern uint Tbsip_Submit_Command(IntPtr context,uint locality,uint priority,byte[] request,uint bytes,byte[] response,ref uint count);
        [DllImport("tbs.dll")] private static extern uint Tbsip_Context_Close(IntPtr context);
        private IntPtr context;private readonly AuthorityIdentity identity;private readonly HardwareKey key;
        internal FixedNvAuthority(AuthorityIdentity identity,HardwareKey key)
        {
            FixedServiceIdentity.Require();if(!Wire.Equal(identity.AuthorityKey,key.PublicBlob)) throw new SecurityException("NV signer differs from commissioned key.");
            this.identity=identity;this.key=key;Parameters parameters=new Parameters {Version=2,Flags=4};uint result=Tbsi_Context_Create(ref parameters,out context);
            if(result!=0 || context==IntPtr.Zero) {Dispose();throw new SecurityException("Actual TPM2 TBS context unavailable: 0x"+result.ToString("x8"));}
            PlatformCustodyProtocol.CheckFamily(Send(PlatformCustodyProtocol.FamilyRequest()));
        }
        private byte[] Send(byte[] request)
        {
            FixedServiceIdentity.Require();if(context==IntPtr.Zero) throw new ObjectDisposedException("FixedNvAuthority");
            byte[] input=Wire.Copy(request,10,1024),response=new byte[4096];uint count=4096;
            try {uint result=Tbsip_Submit_Command(context,0,200,input,(uint)input.Length,response,ref count);
                if(result!=0 || count<10 || count>4096) throw new SecurityException("Actual bounded TBS operation refused: 0x"+result.ToString("x8"));
                Array.Resize(ref response,(int)count);return response;
            } finally {Array.Clear(input,0,input.Length);}
        }
        private bool Public()
        {
            TpmWriteProtocol.Response response=new TpmWriteProtocol.Response(Send(PlatformCustodyProtocol.NvPublicRequest(identity.Domain)),0x8001);
            byte[] actual=response.Two(46,46),name=response.Two(34,34);response.End();
            foreach(bool written in new bool[]{false,true}) if(Wire.Equal(actual,TpmWriteProtocol.NvPublic(identity.AuthorityKey,identity.Domain,identity.Installation,written)) &&
                Wire.Equal(name,TpmWriteProtocol.NvName(identity.AuthorityKey,identity.Domain,identity.Installation,written))) return written;
            throw new SecurityException("Actual NV public Name, policy or attributes differ from fixed custody.");
        }
        internal string ReadHead()
        {
            if(!Public()) return new string('0',64);
            TpmWriteProtocol.Response response=new TpmWriteProtocol.Response(Send(PlatformCustodyProtocol.HeadRequest(identity.Domain)),0x8002);
            if(response.U32()!=34) throw new SecurityException("NV head parameter area differs.");byte[] head=response.Two(32,32);
            if(response.U16()!=0 || response.U8()!=1 || response.U16()!=0) throw new SecurityException("NV read password response differs.");response.End();return Wire.Hex(head);
        }
        internal TpmEpoch ReadEpoch()
        {
            TpmWriteProtocol.Response response=new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Request(0x8001,0x181)),0x8001);
            ulong time=response.U64(),clock=response.U64();uint reset=response.U32(),restart=response.U32();byte safe=response.U8();response.End();
            if(safe>1) throw new SecurityException("Actual TPM2_ReadClock safe flag differs.");return new TpmEpoch(time,clock,reset,restart,safe==1);
        }
        internal void Define(byte[] ownerAuth)
        {
            TpmWriteProtocol.Response capability=new TpmWriteProtocol.Response(Send(PlatformCustodyProtocol.IndexRequest(identity.Domain)),0x8001);
            byte more=capability.U8();uint kind=capability.U32(),count=capability.U32();
            if(more>1 || kind!=1 || count>1) throw new SecurityException("TPM handle capability response differs.");
            if(count==1) {uint actual=capability.U32();capability.End();if(actual<=PlatformCustodyProtocol.Index(identity.Domain)) throw new SecurityException("Fixed NV slot is already occupied; never adopt or replace it.");}
            else capability.End();
            byte[] command=TpmWriteProtocol.Define(identity.AuthorityKey,identity.Domain,identity.Installation,ownerAuth);
            try {CheckEmptyAuthorization(Send(command),true);} finally {Array.Clear(command,0,command.Length);}
            if(Public()) throw new SecurityException("Newly defined NV unexpectedly has prior history.");
        }
        internal void EnsureDefinedForPendingGenesis(byte[] ownerAuth)
        {
            // A protected pending identity plus a genuine signed genesis must
            // already exist. Existing objects are matched in full, never reset.
            TpmWriteProtocol.Response capability=new TpmWriteProtocol.Response(Send(PlatformCustodyProtocol.IndexRequest(identity.Domain)),0x8001);
            byte more=capability.U8();uint kind=capability.U32(),count=capability.U32();
            if(more>1 || kind!=1 || count>1) throw new SecurityException("TPM pending-slot capability differs.");
            uint observed=count==1?capability.U32():0;capability.End();
            if(count==1 && observed==PlatformCustodyProtocol.Index(identity.Domain)) {Public();return;}
            if(count==1 && observed<PlatformCustodyProtocol.Index(identity.Domain)) throw new SecurityException("TPM capability returned an unexpected lower namespace.");
            Define(ownerAuth);
        }
        private static void CheckEmptyAuthorization(byte[] value,bool password=false)
        {
            TpmWriteProtocol.Response response=new TpmWriteProtocol.Response(value,0x8002);
            if(response.U32()!=0) throw new SecurityException("Unexpected TPM write response parameters.");
            byte[] nonce=response.Two(0,32);
            if((password && nonce.Length!=0) || response.U8()!=(password?1:0) || response.U16()!=0) throw new SecurityException("Unexpected TPM write authorization response.");response.End();
        }
        internal void Extend(string previousHead,string recordDigest,Action check)
        {
            if(check==null) throw new ArgumentNullException("check");check();
            if(ReadHead()!=previousHead) throw new SecurityException("NV head changed before exact journal extension.");
            bool written=Public();uint external=0,session=0;
            try {
                TpmWriteProtocol.Response loaded=new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Load(identity.AuthorityKey)),0x8001);
                external=loaded.U32();if((external>>24)!=0x80 || !Wire.Equal(loaded.Two(34,34),TpmWriteProtocol.KeyName(identity.AuthorityKey))) throw new SecurityException("Loaded TPM public key Name differs.");loaded.End();
                TpmWriteProtocol.Response started=new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Start(Wire.Random(32))),0x8001);
                session=started.U32();if((session>>24)!=3) throw new SecurityException("TPM did not return a policy session.");byte[] nonce=started.Two(16,32);started.End();
                byte[] cpHash=TpmWriteProtocol.ExtendCpHash(identity.AuthorityKey,identity.Domain,identity.Installation,written,Wire.Bytes(recordDigest,32,true));
                byte[] reference=TpmWriteProtocol.PolicyReference(identity.Domain,identity.Installation);
                check();byte[] signature=key.Sign(TpmWriteProtocol.AuthorizationInput(nonce,cpHash,reference));
                TpmWriteProtocol.Response authorized=new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Signed(external,session,nonce,cpHash,reference,signature)),0x8001);
                if(authorized.U16()!=0 || authorized.U16()!=0x8025 || authorized.U32()!=0x40000007 || authorized.U16()!=0) throw new SecurityException("TPM returned an unexpected policy ticket.");authorized.End();
                new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Restrict(session)),0x8001).End();
                TpmWriteProtocol.Response digest=new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Digest(session)),0x8001);
                if(!Wire.Equal(digest.Two(32,32),TpmWriteProtocol.Policy(identity.AuthorityKey,identity.Domain,identity.Installation))) throw new SecurityException("Actual TPM policy digest differs.");digest.End();
                check();if(ReadHead()!=previousHead) throw new SecurityException("NV head changed during nonce-bound authorization.");
                CheckEmptyAuthorization(Send(TpmWriteProtocol.Apply(identity.Domain,session,Wire.Bytes(recordDigest,32,true))));session=0;
                string expected=Wire.Hash(Wire.Join(Wire.Bytes(previousHead,32,false),Wire.Bytes(recordDigest,32,true)));
                if(ReadHead()!=expected) throw new SecurityException("Actual NV extension outcome differs; preserve pending journal.");check();
            } finally {
                if(session!=0) {try {new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Flush(session)),0x8001).End();} catch(SecurityException) { }}
                if(external!=0) {try {new TpmWriteProtocol.Response(Send(TpmWriteProtocol.Flush(external)),0x8001).End();} catch(SecurityException) { }}
            }
        }
        public void Dispose() {if(context!=IntPtr.Zero){Tbsip_Context_Close(context);context=IntPtr.Zero;}}
    }
}
