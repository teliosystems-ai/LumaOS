using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Luma.Windows.Hosted
{
    // The binary formats below are closed and domain-separated. Decoding signed
    // bytes never establishes custody, time, installation or effect authority.
    public static class Wire
    {
        public const int MaximumFrame = 65536;
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        public static byte[] Copy(byte[] value, int minimum, int maximum)
        {
            if(value == null || value.Length < minimum || value.Length > maximum)
                throw new InvalidDataException("Hosted input exceeds its exact bound.");
            return (byte[])value.Clone();
        }
        public static byte[] Join(params byte[][] values)
        {
            using(MemoryStream stream = new MemoryStream()) {
                try {
                    foreach(byte[] value in values) {
                        if(value == null || value.Length > MaximumFrame || stream.Length + value.Length > MaximumFrame)
                            throw new InvalidDataException("Hosted wire frame exceeds its bound.");
                        stream.Write(value,0,value.Length);
                    }
                    return stream.ToArray();
                } finally {byte[] buffer=stream.GetBuffer();Array.Clear(buffer,0,buffer.Length);}
            }
        }
        public static byte[] HashBytes(byte[] value)
        {
            if(value == null || value.Length > MaximumFrame) throw new InvalidDataException("Hosted hash input exceeds its bound.");
            using(SHA256 hash=SHA256.Create()) return hash.ComputeHash(value);
        }
        public static string Hash(byte[] value) { return Hex(HashBytes(value)); }
        public static string Hex(byte[] value)
        {
            if(value == null || value.Length > MaximumFrame) throw new InvalidDataException("Hosted hex exceeds its bound.");
            return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
        }
        public static byte[] Bytes(string value, int count, bool nonzero)
        {
            if(count < 1 || count > MaximumFrame/2 || value == null || value.Length != count*2 || !Regex.IsMatch(value,"\\A[0-9a-f]+\\z"))
                throw new InvalidDataException("Hosted identity requires exact canonical hexadecimal.");
            byte[] result=new byte[count]; bool any=false;
            for(int index=0;index<count;index++) {result[index]=Convert.ToByte(value.Substring(index*2,2),16);any|=result[index]!=0;}
            if(nonzero && !any) throw new InvalidDataException("Hosted identity cannot be an uncommissioned zero value.");
            return result;
        }
        public static bool Equal(byte[] left, byte[] right)
        {
            if(left == null || right == null || left.Length != right.Length) return false;
            int difference=0;for(int index=0;index<left.Length;index++) difference|=left[index]^right[index];
            return difference==0;
        }
        public static byte[] Random(int count)
        {
            if(count<16 || count>64) throw new InvalidDataException("Hosted nonce length refused.");
            byte[] result=new byte[count];using(RandomNumberGenerator random=RandomNumberGenerator.Create()) random.GetBytes(result);return result;
        }
        public static string Sid(string value)
        {
            if(value == null || value.Length>184 || !Regex.IsMatch(value,"\\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\\z"))
                throw new SecurityException("An explicit actual local/domain account SID is required.");
            System.Security.Principal.SecurityIdentifier sid=new System.Security.Principal.SecurityIdentifier(value);
            if(sid.Value!=value) throw new SecurityException("Noncanonical hosted account SID.");return value;
        }
        public static string Environment(string value)
        {
            if(value!="lab" && value!="production") throw new InvalidDataException("Unsupported hosted release environment.");return value;
        }
        public sealed class Writer : IDisposable
        {
            private readonly MemoryStream stream=new MemoryStream();
            public Writer(string purpose) { Text(purpose,128); }
            private void Bound() {if(stream.Length>MaximumFrame) throw new InvalidDataException("Hosted frame exceeds its bound.");}
            public void U8(byte value) {stream.WriteByte(value);Bound();}
            public void U16(ushort value) {U8((byte)(value>>8));U8(unchecked((byte)value));}
            public void U32(uint value) {U16((ushort)(value>>16));U16(unchecked((ushort)value));}
            public void U64(ulong value) {U32((uint)(value>>32));U32(unchecked((uint)value));}
            public void Fixed(byte[] value,int count) {if(value==null || value.Length!=count) throw new InvalidDataException("Hosted fixed field size differs.");stream.Write(value,0,count);Bound();}
            public void Blob(byte[] value,int maximum) {if(value==null || value.Length>maximum || maximum>MaximumFrame-4) throw new InvalidDataException("Hosted blob exceeds its bound.");U32((uint)value.Length);Fixed(value,value.Length);}
            public void Text(string value,int maximum) {if(value==null || value.IndexOf('\0')>=0) throw new InvalidDataException("Hosted text is missing or contains NUL.");Blob(Utf8.GetBytes(value),maximum);}
            public byte[] Bytes() {return stream.ToArray();}
            public void Dispose() {byte[] bytes=stream.GetBuffer();Array.Clear(bytes,0,bytes.Length);stream.Dispose();}
        }
        public sealed class Reader : IDisposable
        {
            private readonly byte[] input;private int offset;
            public Reader(byte[] value,string purpose) {input=Copy(value,1,MaximumFrame);if(Text(128)!=purpose) throw new InvalidDataException("Hosted wire purpose differs.");}
            public byte[] Fixed(int count) {if(count<0 || count>input.Length-offset) throw new InvalidDataException("Hosted frame truncated.");byte[] value=new byte[count];Buffer.BlockCopy(input,offset,value,0,count);offset+=count;return value;}
            public byte U8() {return Fixed(1)[0];}
            public ushort U16() {return (ushort)(((uint)U8()<<8)|U8());}
            public uint U32() {return ((uint)U16()<<16)|U16();}
            public ulong U64() {return ((ulong)U32()<<32)|U32();}
            public byte[] Blob(int maximum) {uint length=U32();if(length>(uint)maximum) throw new InvalidDataException("Hosted blob exceeds its bound.");return Fixed((int)length);}
            public string Text(int maximum) {string result=Utf8.GetString(Blob(maximum));if(result.IndexOf('\0')>=0) throw new InvalidDataException("Hosted text contains NUL.");return result;}
            public void End() {if(offset!=input.Length) throw new InvalidDataException("Trailing hosted wire data.");}
            public void Dispose() {Array.Clear(input,0,input.Length);offset=input.Length;}
        }
    }

    public sealed class AuthorityIdentity
    {
        public string Domain {get;private set;}
        public string Installation {get;private set;}
        public string FirstAdminSid {get;private set;}
        public string Environment {get;private set;}
        public string ServiceSha256 {get;private set;}
        public string WslSha256 {get;private set;}
        private byte[] releaseKey,timeKey,authorityKey;
        public byte[] ReleaseKey {get{return (byte[])releaseKey.Clone();}}
        public byte[] TimeKey {get{return (byte[])timeKey.Clone();}}
        public byte[] AuthorityKey {get{return (byte[])authorityKey.Clone();}}
        public string AuthorityKeySha256 {get{return Wire.Hash(authorityKey);}}
        public AuthorityIdentity(string domain,string installation,string firstAdminSid,string environment,
            byte[] releasePublicBlob,byte[] timePublicBlob,byte[] authorityPublicBlob,string serviceSha256,string wslSha256)
        {
            PlatformCustodyProtocol.Index(domain);Domain=domain;
            Wire.Bytes(installation,32,true);Wire.Sid(firstAdminSid);Wire.Environment(environment);
            Wire.Bytes(serviceSha256,32,true);Wire.Bytes(wslSha256,32,true);
            releaseKey=Public(releasePublicBlob);timeKey=Public(timePublicBlob);authorityKey=Public(authorityPublicBlob);
            if(Wire.Equal(releaseKey,timeKey) || Wire.Equal(releaseKey,authorityKey) || Wire.Equal(timeKey,authorityKey))
                throw new SecurityException("Release, UTC and local custody keys must be independent.");
            Installation=installation;FirstAdminSid=firstAdminSid;Environment=environment;ServiceSha256=serviceSha256;WslSha256=wslSha256;
        }
        internal static byte[] Public(byte[] value)
        {
            byte[] result=Wire.Copy(value,72,72);byte[] header={0x45,0x43,0x53,0x31,0x20,0,0,0};
            for(int index=0;index<header.Length;index++) if(result[index]!=header[index]) throw new InvalidDataException("Hosted key requires exact P256 public CNG blob.");
            return result;
        }
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-identity-v1")) {
                writer.Text(Domain,32);writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.Text(FirstAdminSid,184);writer.Text(Environment,10);
                writer.Fixed(releaseKey,72);writer.Fixed(timeKey,72);writer.Fixed(authorityKey,72);
                writer.Fixed(Wire.Bytes(ServiceSha256,32,true),32);writer.Fixed(Wire.Bytes(WslSha256,32,true),32);return writer.Bytes();
            }
        }
        public static AuthorityIdentity Decode(byte[] value)
        {
            Wire.Reader reader=new Wire.Reader(value,"luma-windows-hosted-identity-v1");
            AuthorityIdentity result=new AuthorityIdentity(reader.Text(32),Wire.Hex(reader.Fixed(32)),reader.Text(184),reader.Text(10),
                reader.Fixed(72),reader.Fixed(72),reader.Fixed(72),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)));
            reader.End();if(!Wire.Equal(result.Encode(),value)) throw new InvalidDataException("Noncanonical hosted identity.");return result;
        }
    }

    public enum JournalKind : byte { Commission=1,ImportPrepared=2,Imported=3,ActivationPrepared=4,Activated=5,UpdatePrepared=6,RollbackPrepared=7,Cancelled=8,ControllerStarted=9,ControllerCompleted=10,NvWriteAborted=11,TrustChanged=12,TrustPrepared=13,TrustCancelled=14,RuntimePrepared=15,RuntimeActivated=16,RuntimeCancelled=17,FileEnrolled=18,FileEnrollmentRevoked=19,ComputePrepared=20,ComputeObserved=21,InferencePrepared=22,InferenceObserved=23,WorkspacePrepared=24,WorkspaceObserved=25 }
    public sealed class JournalEntry
    {
        public ulong Sequence {get;private set;}
        public JournalKind Kind {get;private set;}
        public string PreviousHead {get;private set;}
        public string PreviousRecord {get;private set;}
        public string ActorSid {get;private set;}
        private byte[] payload,preimage,wire;
        public byte[] Payload {get{return (byte[])payload.Clone();}}
        public byte[] SigningInput {get{return (byte[])preimage.Clone();}}
        public byte[] Bytes {get {if(wire==null) throw new SecurityException("Unsigned journal entry has no publishable record.");return (byte[])wire.Clone();}}
        public string RecordSha256 {get{return Wire.Hash(Bytes);}}
        public string NextHead {get{return Wire.Hash(Wire.Join(Wire.Bytes(PreviousHead,32,false),Wire.Bytes(RecordSha256,32,true)));}}
        private JournalEntry() {}
        public static JournalEntry Prepare(AuthorityIdentity identity,ulong sequence,JournalKind kind,string previousHead,string previousRecord,string actorSid,byte[] payload)
        {
            if(identity==null || sequence<1 || sequence>1024 || !Enum.IsDefined(typeof(JournalKind),kind)) throw new InvalidDataException("Unsupported hosted journal sequence or kind.");
            Wire.Bytes(previousHead,32,sequence!=1);Wire.Bytes(previousRecord,32,sequence!=1);Wire.Sid(actorSid);
            if(actorSid!=identity.FirstAdminSid || (sequence==1)!=(kind==JournalKind.Commission) ||
                (sequence==1 && (previousHead!=new string('0',64) || previousRecord!=new string('0',64))))
                throw new SecurityException("Hosted journal actor/genesis differs from explicit commissioning.");
            if(kind==JournalKind.FileEnrolled || kind==JournalKind.FileEnrollmentRevoked) FileEnrollmentRecord.Decode(payload).Envelope(identity,kind,previousHead);
            if(kind==JournalKind.WorkspacePrepared) HostedWorkspacePreparation.Decode(payload).RequireIdentity(identity,actorSid);
            JournalEntry result=new JournalEntry {Sequence=sequence,Kind=kind,PreviousHead=previousHead,PreviousRecord=previousRecord,
                ActorSid=actorSid,payload=Wire.Copy(payload,1,4096)};
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-journal-v1")) {
                writer.Fixed(Wire.Bytes(Wire.Hash(identity.Encode()),32,true),32);writer.U64(sequence);writer.U8((byte)kind);
                writer.Fixed(Wire.Bytes(previousHead,32,false),32);writer.Fixed(Wire.Bytes(previousRecord,32,false),32);
                writer.Text(actorSid,184);writer.Blob(result.payload,4096);result.preimage=writer.Bytes();
            }
            return result;
        }
        public JournalEntry Signed(AuthorityIdentity identity,byte[] value)
        {
            byte[] actual=Wire.Copy(value,64,64);
            if(!PlatformSignature.Verify(identity.AuthorityKey,preimage,actual)) throw new SecurityException("Hosted journal signature refused.");
            JournalEntry result=Prepare(identity,Sequence,Kind,PreviousHead,PreviousRecord,ActorSid,payload);
            if(!Wire.Equal(preimage,result.preimage)) throw new SecurityException("Hosted journal identity substitution.");
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-signed-journal-v1")) {writer.Blob(preimage,20000);writer.Fixed(actual,64);result.wire=writer.Bytes();}
            return result;
        }
        public static JournalEntry Decode(AuthorityIdentity identity,byte[] value)
        {
            Wire.Reader outer=new Wire.Reader(value,"luma-windows-hosted-signed-journal-v1");byte[] input=outer.Blob(20000),signature=outer.Fixed(64);outer.End();
            Wire.Reader reader=new Wire.Reader(input,"luma-windows-hosted-journal-v1");
            if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(identity.Encode())) throw new SecurityException("Hosted journal installation/key/anchors differ.");
            ulong sequence=reader.U64();JournalKind kind=(JournalKind)reader.U8();string previous=Wire.Hex(reader.Fixed(32)),record=Wire.Hex(reader.Fixed(32)),actor=reader.Text(184);
            byte[] payload=reader.Blob(4096);reader.End();
            JournalEntry result=Prepare(identity,sequence,kind,previous,record,actor,payload).Signed(identity,signature);
            if(!Wire.Equal(result.Bytes,value)) throw new InvalidDataException("Noncanonical hosted journal record.");return result;
        }
    }

    public enum RecoveryPhase { Clean,PreparedNotExtended,ExtendedNotPublished,AlreadyPublished }
    public sealed class JournalHistory
    {
        public ulong Sequence {get;private set;}
        public string Head {get;private set;}
        public string Record {get;private set;}
        public JournalEntry Last {get;private set;}
        public EnrolledFileRegistry FileEnrollments {get;private set;}
        private readonly List<JournalEntry> entries=new List<JournalEntry>();
        public JournalEntry[] Entries {get{return entries.ToArray();}}
        private JournalHistory() {Head=new string('0',64);Record=new string('0',64);}
        public static JournalHistory Replay(AuthorityIdentity identity,byte[][] records)
        {return Replay(identity,records,delegate {});}
        public static JournalHistory Replay(AuthorityIdentity identity,byte[][] records,Action check)
        {
            if(identity==null || records==null || records.Length>1024 || check==null) throw new InvalidDataException("Hosted journal exceeds entry bound or lacks its continuous check.");
            check();
            JournalHistory result=new JournalHistory();int bytes=0;
            foreach(byte[] record in records) {
                check();
                if(record==null || record.Length>20000 || checked(bytes+=record.Length)>8*1024*1024) throw new InvalidDataException("Hosted journal exceeds aggregate bound.");
                JournalEntry entry=JournalEntry.Decode(identity,record);
                if(entry.Sequence!=result.Sequence+1 || entry.PreviousHead!=result.Head || entry.PreviousRecord!=result.Record)
                    throw new SecurityException("Hosted journal fork, gap, replay or head rollback.");
                if(entry.Kind==JournalKind.NvWriteAborted) NvAbortEvent.Decode(identity,entry.Payload).Matches(entry);
                result.entries.Add(entry);result.Last=entry;result.Sequence=entry.Sequence;result.Record=entry.RecordSha256;result.Head=entry.NextHead;
            }
            result.FileEnrollments=EnrolledFileRegistry.Replay(identity,result,check);check();return result;
        }
        public RecoveryPhase Reconcile(AuthorityIdentity identity,byte[] pending,string observedHead)
        {
            Wire.Bytes(observedHead,32,Sequence!=0);
            if(pending==null) {
                if(observedHead!=Head) throw new SecurityException("TPM head differs from complete durable journal; refuse repair.");return RecoveryPhase.Clean;
            }
            JournalEntry entry=JournalEntry.Decode(identity,pending);
            if(Last!=null && Wire.Equal(Last.Bytes,pending)) {
                if(observedHead!=Head) throw new SecurityException("Published pending record has a different actual TPM head.");return RecoveryPhase.AlreadyPublished;
            }
            if(entry.Sequence!=Sequence+1 || entry.PreviousHead!=Head || entry.PreviousRecord!=Record)
                throw new SecurityException("Pending journal record does not extend exact current history.");
            if(observedHead==Head) return RecoveryPhase.PreparedNotExtended;
            if(observedHead==entry.NextHead) return RecoveryPhase.ExtendedNotPublished;
            throw new SecurityException("Damaged or substituted hosted authority has no safe automatic recovery.");
        }
    }
}
