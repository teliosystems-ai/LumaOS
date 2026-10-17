using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Luma.Windows
{
    // An explicit commissioned selection, not proof that its caller has
    // enrolled custody. No key/NV object is created or repaired by this code.
    public sealed class PlatformCustodyConfiguration
    {
        public string Domain { get; private set; }
        public string Installation { get; private set; }
        public string KeyName { get; private set; }
        public string PublicKeySha256 { get; private set; }
        public string PolicyHex { get; private set; }
        public string NvNameHex { get; private set; }
        public string ExpectedHeadHex { get; private set; }
        private byte[] publicBlob;
        public byte[] PublicBlob { get { return (byte[])publicBlob.Clone(); } }
        public uint NvIndex { get { return PlatformCustodyProtocol.Index(Domain); } }
        private PlatformCustodyConfiguration() {}

        public static PlatformCustodyConfiguration Commissioned(string domain, string installation,
            string publicBlobHex, string publicKeySha256, string policyHex, string nvNameHex, string expectedHeadHex)
        {
            PlatformCustodyProtocol.Index(domain);
            PlatformCustodyProtocol.NonzeroHex(installation, 32);
            byte[] blob = PlatformCustodyProtocol.Hex(publicBlobHex, 72);
            byte[] magic = new byte[] {0x45,0x43,0x53,0x31,0x20,0,0,0};
            for(int i=0;i<magic.Length;i++) if(blob[i]!=magic[i]) throw new InvalidDataException("Commissioned key is not exact ECDSA P256 ECCPUBLICBLOB.");
            PlatformCustodyProtocol.NonzeroHex(publicKeySha256, 32);
            if(PlatformCustodyProtocol.Hash(blob)!=publicKeySha256) throw new InvalidDataException("Commissioned public key pin mismatch.");
            PlatformCustodyProtocol.NonzeroHex(policyHex, 32);
            PlatformCustodyProtocol.NonzeroHex(expectedHeadHex, 32);
            PlatformCustodyProtocol.Hex(nvNameHex, 34);
            if(nvNameHex!=PlatformCustodyProtocol.ExpectedNvName(domain,policyHex))
                throw new InvalidDataException("Commissioned NV Name does not bind the complete fixed NV public policy.");
            return new PlatformCustodyConfiguration {Domain=domain,Installation=installation,
                KeyName="LumaOS.HostedAuthority.v1."+(domain=="host-deployment"?"host":"content")+"."+installation+".signing",
                PublicKeySha256=publicKeySha256,publicBlob=blob,PolicyHex=policyHex,
                NvNameHex=nvNameHex,ExpectedHeadHex=expectedHeadHex};
        }
    }

    public static class PlatformCustodyProtocol
    {
        // W and X are separate Windows namespaces. Native Admin A, resource R
        // and future native content C remain untouched on dual-boot machines.
        public const uint HostIndex=0x01804c57;
        public const uint ContentIndex=0x01804c58;
        // WRITTEN | NO_DA | AUTHREAD | TPM_NT_EXTEND | POLICYWRITE. No owner
        // writes, AUTHWRITE, ordinary NV_Write, ORDERLY or volatile clearing.
        public const uint Attributes=0x22040048;
        public static uint Index(string domain)
        {
            if(domain=="host-deployment") return HostIndex;
            if(domain=="content-authority") return ContentIndex;
            throw new InvalidDataException("Only the fixed Windows host/content custody domains are supported.");
        }
        public static byte[] Hex(string value,int length)
        {
            if(length<1 || length>4096 || value==null || value.Length!=length*2 || !Regex.IsMatch(value,"\\A[0-9a-f]+\\z"))
                throw new InvalidDataException("Custody fields require canonical fixed-length lowercase hexadecimal.");
            byte[] result=new byte[length];
            for(int i=0;i<length;i++) result[i]=Convert.ToByte(value.Substring(i*2,2),16);
            return result;
        }
        public static byte[] NonzeroHex(string value,int length)
        {
            byte[] result=Hex(value,length); bool any=false;
            foreach(byte b in result) any|=b!=0;
            if(!any) throw new InvalidDataException("An uncommissioned zero custody identity is forbidden.");
            return result;
        }
        public static string Encode(byte[] value)
        {
            if(value==null || value.Length>8192) throw new InvalidDataException("Custody encoding exceeds fixed bound.");
            return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();
        }
        public static string Hash(byte[] value)
        {
            if(value==null || value.Length>8192) throw new InvalidDataException("Custody hashing exceeds fixed bound.");
            using(SHA256 hash=SHA256.Create()) return Encode(hash.ComputeHash(value));
        }
        private static void U16(Stream stream,ushort value) { stream.WriteByte((byte)(value>>8));stream.WriteByte((byte)value); }
        private static void U32(Stream stream,uint value) { stream.WriteByte((byte)(value>>24));stream.WriteByte((byte)(value>>16));stream.WriteByte((byte)(value>>8));stream.WriteByte((byte)value); }
        private static byte[] Request(ushort tag,uint command,byte[] body)
        {
            using(MemoryStream stream=new MemoryStream()) { U16(stream,tag);U32(stream,(uint)(10+body.Length));U32(stream,command);stream.Write(body,0,body.Length);return stream.ToArray(); }
        }
        public static byte[] FamilyRequest()
        {
            using(MemoryStream body=new MemoryStream()) { U32(body,6);U32(body,0x100);U32(body,1);return Request(0x8001,0x17a,body.ToArray()); }
        }
        public static byte[] IndexRequest(string domain)
        {
            using(MemoryStream body=new MemoryStream()) { U32(body,1);U32(body,Index(domain));U32(body,1);return Request(0x8001,0x17a,body.ToArray()); }
        }
        public static byte[] NvPublicRequest(string domain)
        {
            using(MemoryStream body=new MemoryStream()) { U32(body,Index(domain));return Request(0x8001,0x169,body.ToArray()); }
        }
        public static byte[] HeadRequest(string domain)
        {
            using(MemoryStream body=new MemoryStream()) {
                uint index=Index(domain);U32(body,index);U32(body,index);U32(body,9);
                U32(body,0x40000009);U16(body,0);body.WriteByte(1);U16(body,0);U16(body,32);U16(body,0);
                return Request(0x8002,0x14e,body.ToArray());
            }
        }
        public static bool IsReadOnlyCommand(string domain,byte[] value)
        {
            if(value==null || value.Length>64) return false;
            foreach(byte[] allowed in new byte[][] {FamilyRequest(),IndexRequest(domain),NvPublicRequest(domain),HeadRequest(domain)})
                if(Equal(value,allowed)) return true;
            return false;
        }
        private static bool Equal(byte[] a,byte[] b)
        {
            if(a.Length!=b.Length) return false;
            for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false;
            return true;
        }
        public static byte[] ExpectedNvPublic(string domain,string policyHex)
        {
            byte[] policy=NonzeroHex(policyHex,32);
            using(MemoryStream body=new MemoryStream()) {
                U32(body,Index(domain));U16(body,0x000b);U32(body,Attributes);U16(body,32);body.Write(policy,0,32);U16(body,32);
                return body.ToArray();
            }
        }
        public static string ExpectedNvName(string domain,string policyHex)
        {
            return "000b"+Hash(ExpectedNvPublic(domain,policyHex));
        }
        private sealed class Reader
        {
            private byte[] value;private int position;
            public Reader(byte[] data,ushort tag)
            {
                if(data==null || data.Length<10 || data.Length>512) throw new InvalidDataException("TPM response exceeds fixed framing bound.");
                value=(byte[])data.Clone();ushort actual=U16();uint length=U32();uint result=U32();
                if(length!=value.Length) throw new InvalidDataException("TPM response length mismatch.");
                if(result!=0) throw new InvalidDataException("TPM command refused: 0x"+result.ToString("x8"));
                if(actual!=tag) throw new InvalidDataException("Unexpected TPM response session tag.");
            }
            public byte[] Bytes(int count)
            {
                if(count<0 || count>value.Length-position) throw new InvalidDataException("Truncated TPM response.");
                byte[] result=new byte[count];Buffer.BlockCopy(value,position,result,0,count);position+=count;return result;
            }
            public byte Byte() { return Bytes(1)[0]; }
            public ushort U16() { byte[] b=Bytes(2);return (ushort)(((uint)b[0]<<8)|b[1]); }
            public uint U32() { byte[] b=Bytes(4);return ((uint)b[0]<<24)|((uint)b[1]<<16)|((uint)b[2]<<8)|b[3]; }
            public void End() { if(position!=value.Length) throw new InvalidDataException("Trailing TPM response data."); }
        }
        public static void CheckFamily(byte[] response)
        {
            Reader r=new Reader(response,0x8001);if(r.Byte()>1 || r.U32()!=6 || r.U32()!=1 || r.U32()!=0x100 || r.U32()!=0x322e3000)
                throw new InvalidDataException("TPM2 family capability is not exact.");r.End();
        }
        public static void CheckIndex(string domain,byte[] response)
        {
            Reader r=new Reader(response,0x8001);if(r.Byte()>1 || r.U32()!=1 || r.U32()!=1 || r.U32()!=Index(domain))
                throw new InvalidDataException("The commissioned fixed TPM index is missing or substituted.");r.End();
        }
        public static void CheckNvPublic(PlatformCustodyConfiguration configuration,byte[] response)
        {
            if(configuration==null) throw new ArgumentNullException("configuration");
            Reader r=new Reader(response,0x8001);
            if(r.U16()!=46) throw new InvalidDataException("Unexpected complete TPM NV public size.");
            byte[] actual=r.Bytes(46);
            if(!Equal(actual,ExpectedNvPublic(configuration.Domain,configuration.PolicyHex)) || r.U16()!=34 ||
                Encode(r.Bytes(34))!=configuration.NvNameHex) throw new InvalidDataException("TPM NV public Name, attributes or commissioned policy changed.");
            r.End();
        }
        public static byte[] CheckHead(PlatformCustodyConfiguration configuration,byte[] response)
        {
            if(configuration==null) throw new ArgumentNullException("configuration");
            Reader r=new Reader(response,0x8002);
            if(r.U32()!=34 || r.U16()!=32) throw new InvalidDataException("TPM head parameter area is not exactly SHA256.");
            byte[] head=r.Bytes(32);
            // Password sessions have empty nonce/HMAC and continueSession SET
            // in the response, even though no persistent session was allocated.
            if(r.U16()!=0 || r.Byte()!=1 || r.U16()!=0 || Encode(head)!=configuration.ExpectedHeadHex)
                throw new InvalidDataException("TPM head or password-session acknowledgment differs.");
            r.End();return head;
        }
        public static byte[] InspectionInput(PlatformCustodyConfiguration configuration,string nonce)
        {
            if(configuration==null) throw new ArgumentNullException("configuration");NonzeroHex(nonce,32);
            return Encoding.ASCII.GetBytes("luma-windows-hosted-custody-inspection-v1\n"+configuration.Domain+"\n"+
                configuration.Installation+"\n"+configuration.PublicKeySha256+"\n"+configuration.NvNameHex+"\n"+
                configuration.ExpectedHeadHex+"\n"+nonce+"\n");
        }
        public static void CheckKeyPolicy(uint implementation,string algorithm,uint length,uint type,uint usage,
            uint exportPolicy,string actualName,string expectedName)
        {
            if((implementation&1)==0 || (implementation&~0x11U)!=0 || algorithm!="ECDSA_P256" || length!=256 ||
                type!=0x20 || usage!=2 || exportPolicy!=0 || actualName!=expectedName)
                throw new SecurityException("Commissioned key provider, algorithm, machine scope, usage, export policy or name differs.");
        }
        public static void CheckKeySecurity(byte[] descriptor,string serviceSid)
        {
            if(descriptor==null || descriptor.Length<20 || descriptor.Length>65536) throw new SecurityException("Key security descriptor exceeds bound.");
            SecurityIdentifier service=new SecurityIdentifier(serviceSid), system=new SecurityIdentifier("S-1-5-18");
            if(!service.Value.StartsWith("S-1-5-80-",StringComparison.Ordinal)) throw new SecurityException("Fixed service SID is required.");
            RawSecurityDescriptor security=new RawSecurityDescriptor(descriptor,0);
            if(!system.Equals(security.Owner) || (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
                (security.ControlFlags&ControlFlags.DiscretionaryAclPresent)==0 ||
                security.DiscretionaryAcl==null || security.DiscretionaryAcl.Count!=2) throw new SecurityException("Key owner/protected DACL differs.");
            bool foundSystem=false,foundService=false;
            foreach(GenericAce generic in security.DiscretionaryAcl) {
                CommonAce ace=generic as CommonAce;
                if(ace==null || ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags!=AceFlags.None || ace.AccessMask!=0x10000000 || ace.IsCallback)
                    throw new SecurityException("Unsupported key security ACE.");
                if(system.Equals(ace.SecurityIdentifier) && !foundSystem) foundSystem=true;
                else if(service.Equals(ace.SecurityIdentifier) && !foundService) foundService=true;
                else throw new SecurityException("Key DACL contains another principal or duplicate ACE.");
            }
            if(!foundSystem || !foundService) throw new SecurityException("Key DACL lacks exact service/System access.");
        }
    }

    public sealed class PlatformCustodyInspection
    {
        public string Domain,Installation,NvNameHex,HeadHex,PublicKeySha256,Nonce,SignatureHex;
        public readonly string Purpose="luma-windows-hosted-custody-inspection-v1";
        public readonly bool TbsTpm2ReadObserved=true,CommissionedKeyPropertiesObserved=true;
        public readonly bool CommissioningAuthorityAuthenticated=false,KeyAttestationQualified=false;
        public readonly bool PolicySemanticsQualified=false,DurableRollbackProtectionEstablished=false;
        public readonly bool ProtectedUtcEstablished=false,AttestationFreshnessEstablished=false;
        public readonly bool HostedAuthorityEnrollmentComplete=false,ProductInstallationAdmitted=false;
        public readonly bool HardDeadlineEnforced=false,ProductionQualified=false,GateClosing=false;
        internal PlatformCustodyInspection() {}
    }

    // Existing-object inspection/signing only. There is no provisioning,
    // mutation, arbitrary signer, provider/handle override or software fallback.
    public sealed class PlatformCustodyInspector : IDisposable
    {
        private const string ServiceName="LumaHostedAuthority";
        private const string ProviderName="Microsoft Platform Crypto Provider";
        private IntPtr provider,key;
        private readonly object gate=new object();
        private PlatformCustodyConfiguration configuration;
        [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint,ProcessId,Flags; }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatus status,int bytes,out int needed);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool CheckTokenMembership(IntPtr token,byte[] sid,out bool member);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll")] private static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptOpenStorageProvider(out IntPtr provider,string name,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptOpenKey(IntPtr provider,out IntPtr key,string name,uint legacy,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptGetProperty(IntPtr value,string name,byte[] output,uint maximum,out uint bytes,uint flags);
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] private static extern int NCryptExportKey(IntPtr key,IntPtr export,string kind,IntPtr parameters,byte[] output,uint maximum,out uint bytes,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptSignHash(IntPtr key,IntPtr padding,byte[] hash,uint hashBytes,byte[] output,uint maximum,out uint bytes,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptVerifySignature(IntPtr key,IntPtr padding,byte[] hash,uint hashBytes,byte[] signature,uint bytes,uint flags);
        [DllImport("ncrypt.dll")] private static extern int NCryptFreeObject(IntPtr value);
        private PlatformCustodyInspector() {}
        private static void Success(int status,string operation) { if(status!=0) throw new CryptographicException(operation+" failed: 0x"+((uint)status).ToString("x8")); }
        private static SecurityIdentifier CheckService()
        {
            IntPtr threadToken;
            if(OpenThreadToken(GetCurrentThread(),8,true,out threadToken)) {CloseHandle(threadToken);throw new SecurityException("Impersonation is forbidden for the custody service.");}
            int error=Marshal.GetLastWin32Error();if(error!=1008) throw new Win32Exception(error);
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) if(identity.User==null || identity.User.Value!="S-1-5-18")
                throw new SecurityException("The actual LocalSystem service process is required.");
            SecurityIdentifier service=(SecurityIdentifier)new NTAccount("NT SERVICE",ServiceName).Translate(typeof(SecurityIdentifier));
            byte[] sid=new byte[service.BinaryLength];service.GetBinaryForm(sid,0);bool enabled;
            if(!CheckTokenMembership(IntPtr.Zero,sid,out enabled)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if(!enabled) throw new SecurityException("The actual enabled fixed service SID is missing.");
            IntPtr manager=IntPtr.Zero,handle=IntPtr.Zero;
            try {
                manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                handle=OpenService(manager,ServiceName,4);if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                ServiceStatus status;int needed;
                if(!QueryServiceStatusEx(handle,0,out status,Marshal.SizeOf(typeof(ServiceStatus)),out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if(needed>Marshal.SizeOf(typeof(ServiceStatus)) || status.Type!=0x10 || status.State!=4 || status.ProcessId!=GetCurrentProcessId())
                    throw new SecurityException("The fixed running own-process service does not identify this process.");
            } finally {if(handle!=IntPtr.Zero) CloseServiceHandle(handle);if(manager!=IntPtr.Zero) CloseServiceHandle(manager);}
            return service;
        }
        private byte[] Property(IntPtr value,string name,int maximum,uint flags)
        {
            byte[] result=new byte[maximum];uint written;Success(NCryptGetProperty(value,name,result,(uint)result.Length,out written,flags),"Read fixed key property");
            if(written==0 || written>result.Length) throw new SecurityException("Unexpected bounded key property length.");
            Array.Resize(ref result,(int)written);return result;
        }
        private uint Number(IntPtr value,string name)
        {
            byte[] b=Property(value,name,4,0);if(b.Length!=4) throw new SecurityException("Key property is not a DWORD.");return BitConverter.ToUInt32(b,0);
        }
        private string Text(string name)
        {
            byte[] b=Property(key,name,512,0);if(b.Length<2 || b.Length%2!=0 || b[b.Length-1]!=0 || b[b.Length-2]!=0)
                throw new SecurityException("Key text property is not bounded terminated UTF16.");
            string value=new UnicodeEncoding(false,false,true).GetString(b,0,b.Length-2);
            if(value.IndexOf('\0')>=0) throw new SecurityException("Key property has a hidden suffix.");return value;
        }
        private void CheckKey(SecurityIdentifier service)
        {
            PlatformCustodyProtocol.CheckKeyPolicy(Number(provider,"Impl Type"),Text("Algorithm Name"),Number(key,"Length"),
                Number(key,"Key Type"),Number(key,"Key Usage"),Number(key,"Export Policy"),Text("Name"),configuration.KeyName);
            if(Number(provider,"Security Descr Support")!=1) throw new SecurityException("The fixed key provider cannot prove its DACL.");
            PlatformCustodyProtocol.CheckKeySecurity(Property(key,"Security Descr",65536,5),service.Value);
            byte[] blob=new byte[72];uint count;Success(NCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",IntPtr.Zero,blob,72,out count,0),"Export commissioned public key");
            if(count!=72 || PlatformCustodyProtocol.Encode(blob)!=PlatformCustodyProtocol.Encode(configuration.PublicBlob) ||
                PlatformCustodyProtocol.Hash(blob)!=configuration.PublicKeySha256) throw new SecurityException("Actual commissioned key public identity changed.");
        }
        public static PlatformCustodyInspector OpenCommissioned(PlatformCustodyConfiguration configuration)
        {
            if(configuration==null) throw new ArgumentNullException("configuration");
            SecurityIdentifier service=CheckService();PlatformCustodyInspector result=new PlatformCustodyInspector();result.configuration=configuration;
            try {
                Success(NCryptOpenStorageProvider(out result.provider,ProviderName,0),"Open exact TPM CNG provider");
                Success(NCryptOpenKey(result.provider,out result.key,configuration.KeyName,0,0x20|0x40),"Open existing commissioned machine key silently");
                result.CheckKey(service);return result;
            } catch {result.Dispose();throw;}
        }
        public PlatformCustodyInspection InspectAndSign(string nonce)
        {
            lock(gate) {
            if(key==IntPtr.Zero) throw new ObjectDisposedException("PlatformCustodyInspector");
            byte[] input=PlatformCustodyProtocol.InspectionInput(configuration,nonce);
            SecurityIdentifier service=CheckService();CheckKey(service);
            using(TpmReadContext context=new TpmReadContext(configuration.Domain)) {
                PlatformCustodyProtocol.CheckFamily(context.Send(PlatformCustodyProtocol.FamilyRequest()));
                PlatformCustodyProtocol.CheckIndex(configuration.Domain,context.Send(PlatformCustodyProtocol.IndexRequest(configuration.Domain)));
                PlatformCustodyProtocol.CheckNvPublic(configuration,context.Send(PlatformCustodyProtocol.NvPublicRequest(configuration.Domain)));
                PlatformCustodyProtocol.CheckHead(configuration,context.Send(PlatformCustodyProtocol.HeadRequest(configuration.Domain)));
                byte[] digest;using(SHA256 hash=SHA256.Create()) digest=hash.ComputeHash(input);
                byte[] signature=new byte[64];uint count;
                Success(NCryptSignHash(key,IntPtr.Zero,digest,32,signature,64,out count,0x40),"Sign fixed custody inspection");
                if(count!=64) throw new CryptographicException("Unexpected commissioned P1363 signature size.");
                Success(NCryptVerifySignature(key,IntPtr.Zero,digest,32,signature,64,0),"Verify custody inspection signature");
                PlatformCustodyProtocol.CheckNvPublic(configuration,context.Send(PlatformCustodyProtocol.NvPublicRequest(configuration.Domain)));
                PlatformCustodyProtocol.CheckHead(configuration,context.Send(PlatformCustodyProtocol.HeadRequest(configuration.Domain)));
                CheckKey(CheckService());
                return new PlatformCustodyInspection {Domain=configuration.Domain,Installation=configuration.Installation,
                    NvNameHex=configuration.NvNameHex,HeadHex=configuration.ExpectedHeadHex,PublicKeySha256=configuration.PublicKeySha256,
                    Nonce=nonce,SignatureHex=PlatformCustodyProtocol.Encode(signature)};
            }
            }
        }
        public void Dispose() {lock(gate){if(key!=IntPtr.Zero){NCryptFreeObject(key);key=IntPtr.Zero;}if(provider!=IntPtr.Zero){NCryptFreeObject(provider);provider=IntPtr.Zero;}}}
        private sealed class TpmReadContext : IDisposable
        {
            [StructLayout(LayoutKind.Sequential)] private struct Parameters {public uint Version,Flags;}
            [DllImport("tbs.dll")] private static extern uint Tbsi_Context_Create(ref Parameters parameters,out IntPtr context);
            [DllImport("tbs.dll")] private static extern uint Tbsip_Submit_Command(IntPtr context,uint locality,uint priority,byte[] command,uint commandBytes,byte[] response,ref uint responseBytes);
            [DllImport("tbs.dll")] private static extern uint Tbsip_Context_Close(IntPtr context);
            private IntPtr context;private string domain;
            public TpmReadContext(string domain)
            {
                PlatformCustodyProtocol.Index(domain);this.domain=domain;Parameters parameters=new Parameters {Version=2,Flags=4};
                uint status=Tbsi_Context_Create(ref parameters,out context);
                if(status!=0) {if(context!=IntPtr.Zero){Tbsip_Context_Close(context);context=IntPtr.Zero;}throw new SecurityException("TPM2 TBS context unavailable: 0x"+status.ToString("x8"));}
            }
            public byte[] Send(byte[] command)
            {
                if(context==IntPtr.Zero) throw new ObjectDisposedException("TpmReadContext");
                if(!PlatformCustodyProtocol.IsReadOnlyCommand(domain,command)) throw new SecurityException("Only exact fixed read-only TPM commands are admitted.");
                byte[] response=new byte[512];uint count=512;
                uint status=Tbsip_Submit_Command(context,0,200,command,(uint)command.Length,response,ref count);
                if(status!=0 || count<10 || count>512) throw new SecurityException("Read-only TBS command refused or response oversized: 0x"+status.ToString("x8"));
                Array.Resize(ref response,(int)count);return response;
            }
            public void Dispose() {if(context!=IntPtr.Zero){Tbsip_Context_Close(context);context=IntPtr.Zero;}}
        }
    }
}
