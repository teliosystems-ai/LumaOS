using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Text;

namespace Luma.Windows.Hosted
{
    // Publisher-signed deployment descriptions and nonce-signed UTC are distinct
    // from the local host custody key. No wall-clock fallback is accepted.
    public sealed class ReleaseDescriptor
    {
        public string Environment {get;private set;}
        public ulong Sequence {get;private set;}
        public ulong NotBeforeMilliseconds {get;private set;}
        public ulong ExpiresMilliseconds {get;private set;}
        public string PreviousReleaseSha256 {get;private set;}
        public string ManifestSha256 {get;private set;}
        public string RootfsSha256 {get;private set;}
        public long ArchiveBytes {get;private set;}
        public long ContentBytes {get;private set;}
        public int MemberCount {get;private set;}
        public string GuestPlatformSha256 {get;private set;}
        private RequiredFile[] files;
        public RequiredFile[] RequiredFiles {
            get {List<RequiredFile> result=new List<RequiredFile>();foreach(RequiredFile file in files)
                result.Add(new RequiredFile {Path=file.Path,Bytes=file.Bytes,Sha256=file.Sha256,Executable=file.Executable});return result.ToArray();}
        }
        public ReleaseDescriptor(string environment,ulong sequence,ulong notBefore,ulong expires,string previousRelease,
            string manifest,string rootfs,long archiveBytes,long contentBytes,int memberCount,RequiredFile[] requiredFiles)
        {
            Wire.Environment(environment);Wire.Bytes(previousRelease,32,sequence!=1);Wire.Bytes(manifest,32,true);Wire.Bytes(rootfs,32,true);
            if(sequence<1 || sequence>9007199254740991 || notBefore<1 || expires<=notBefore || expires>4102444800000 || expires-notBefore>604800000 ||
                archiveBytes<1024 || archiveBytes>PackageInspector.MaximumArchiveBytes || archiveBytes%512!=0 || contentBytes<1 || contentBytes>PackageInspector.MaximumArchiveBytes ||
                memberCount<1 || memberCount>PackageInspector.MaximumMembers || requiredFiles==null || requiredFiles.Length<4 || requiredFiles.Length>128 ||
                (sequence==1 && previousRelease!=new string('0',64))) throw new InvalidDataException("Hosted release bounds or predecessor differ.");
            List<RequiredFile> copy=new List<RequiredFile>();string previous=null;HashSet<string> selected=new HashSet<string>(StringComparer.Ordinal);
            foreach(RequiredFile file in requiredFiles) {
                if(file==null || PackageInspector.ValidatePath(file.Path)!=file.Path || file.Bytes<0 || file.Bytes>PackageInspector.MaximumArchiveBytes ||
                    (previous!=null && String.CompareOrdinal(previous,file.Path)>=0)) throw new InvalidDataException("Hosted required files must be exact bounded sorted unique names.");
                Wire.Bytes(file.Sha256,32,true);selected.Add(file.Path);previous=file.Path;
                if(file.Path=="usr/bin/luma-platform") {if(!file.Executable || file.Bytes<64) throw new SecurityException("Hosted native executable is missing.");GuestPlatformSha256=file.Sha256;}
                copy.Add(new RequiredFile {Path=file.Path,Bytes=file.Bytes,Sha256=file.Sha256,Executable=file.Executable});
            }
            foreach(string name in new string[]{"etc/os-release","etc/wsl.conf","usr/bin/luma-platform","usr/lib/luma/platform.json"})
                if(!selected.Contains(name)) throw new SecurityException("Hosted release omits a required runtime identity or confinement input.");
            Environment=environment;Sequence=sequence;NotBeforeMilliseconds=notBefore;ExpiresMilliseconds=expires;
            PreviousReleaseSha256=previousRelease;ManifestSha256=manifest;RootfsSha256=rootfs;ArchiveBytes=archiveBytes;ContentBytes=contentBytes;MemberCount=memberCount;files=copy.ToArray();
        }
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-release-v1")) {
                writer.Text(Environment,10);writer.U64(Sequence);writer.U64(NotBeforeMilliseconds);writer.U64(ExpiresMilliseconds);
                writer.Fixed(Wire.Bytes(PreviousReleaseSha256,32,false),32);writer.Fixed(Wire.Bytes(ManifestSha256,32,true),32);writer.Fixed(Wire.Bytes(RootfsSha256,32,true),32);
                writer.U64((ulong)ArchiveBytes);writer.U64((ulong)ContentBytes);writer.U32((uint)MemberCount);writer.U16((ushort)files.Length);
                foreach(RequiredFile file in files) {writer.Text(file.Path,255);writer.U64((ulong)file.Bytes);writer.Fixed(Wire.Bytes(file.Sha256,32,true),32);writer.U8(file.Executable?(byte)1:(byte)0);}return writer.Bytes();
            }
        }
        public static ReleaseDescriptor Decode(byte[] bytes)
        {
            Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-release-v1");string environment=reader.Text(10);
            ulong sequence=reader.U64(),start=reader.U64(),end=reader.U64();string previous=Wire.Hex(reader.Fixed(32)),manifest=Wire.Hex(reader.Fixed(32)),rootfs=Wire.Hex(reader.Fixed(32));
            ulong archive=reader.U64(),content=reader.U64();uint count=reader.U32();ushort number=reader.U16();
            if(archive>Int64.MaxValue || content>Int64.MaxValue || count>Int32.MaxValue || number>128) throw new InvalidDataException("Hosted release integer bound exceeded.");
            List<RequiredFile> files=new List<RequiredFile>();
            for(int index=0;index<number;index++) {string path=reader.Text(255);ulong size=reader.U64();string hash=Wire.Hex(reader.Fixed(32));byte executable=reader.U8();
                if(size>Int64.MaxValue || executable>1) throw new InvalidDataException("Hosted file bound/boolean differs.");
                files.Add(new RequiredFile {Path=path,Bytes=(long)size,Sha256=hash,Executable=executable==1});}
            reader.End();ReleaseDescriptor result=new ReleaseDescriptor(environment,sequence,start,end,previous,manifest,rootfs,(long)archive,(long)content,(int)count,files.ToArray());
            if(!Wire.Equal(result.Encode(),bytes)) throw new InvalidDataException("Noncanonical hosted release.");return result;
        }
        public void Verify(AuthorityIdentity identity,byte[] signature)
        {
            if(identity.Domain!="host-deployment" || identity.Environment!=Environment || !PlatformSignature.Verify(identity.ReleaseKey,SigningInput(),Wire.Copy(signature,64,64)))
                throw new SecurityException("Hosted release signature, domain or commissioned environment differs.");
        }
        public byte[] SigningInput()
        {
            byte[] bytes=Encode();using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-release-signature-v1")) {
                writer.U32((uint)bytes.Length);writer.Fixed(Wire.HashBytes(bytes),32);return writer.Bytes();
            }
        }
    }

    public sealed class TimeAttestation
    {
        public string Installation {get;private set;}
        public string Nonce {get;private set;}
        public string ReleaseSha256 {get;private set;}
        public ulong LowerMilliseconds {get;private set;}
        public ulong UpperMilliseconds {get;private set;}
        public TimeAttestation(string installation,string nonce,string release,ulong lower,ulong upper)
        {
            Wire.Bytes(installation,32,true);Wire.Bytes(nonce,32,true);Wire.Bytes(release,32,true);
            if(lower<1 || upper<lower || upper>4102444800000 || upper-lower>10000) throw new InvalidDataException("UTC attestation uncertainty exceeds ten seconds.");
            Installation=installation;Nonce=nonce;ReleaseSha256=release;LowerMilliseconds=lower;UpperMilliseconds=upper;
        }
        public byte[] Encode()
        {
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-utc-v1")) {
                writer.Fixed(Wire.Bytes(Installation,32,true),32);writer.Fixed(Wire.Bytes(Nonce,32,true),32);writer.Fixed(Wire.Bytes(ReleaseSha256,32,true),32);
                writer.U64(LowerMilliseconds);writer.U64(UpperMilliseconds);return writer.Bytes();
            }
        }
        public static TimeAttestation Decode(byte[] bytes)
        {
            Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-utc-v1");TimeAttestation result=new TimeAttestation(
                Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),Wire.Hex(reader.Fixed(32)),reader.U64(),reader.U64());reader.End();
            if(!Wire.Equal(result.Encode(),bytes)) throw new InvalidDataException("Noncanonical UTC attestation.");return result;
        }
    }

    internal sealed class LiveRelease
    {
        private readonly AuthorityIdentity identity;private readonly ReleaseDescriptor release;private readonly Stopwatch challengeAge;private readonly bool requireReleaseLifetime;
        private readonly string nonce;private TimeAttestation time;private byte[] signature;
        internal LiveRelease(AuthorityIdentity identity,ReleaseDescriptor release)
            :this(identity,release,true) {}
        private LiveRelease(AuthorityIdentity identity,ReleaseDescriptor release,bool lifetime)
        {this.identity=identity;this.release=release;requireReleaseLifetime=lifetime;nonce=Wire.Hex(Wire.Random(32));challengeAge=Stopwatch.StartNew();}
        internal static LiveRelease ForAbandonment(AuthorityIdentity identity,ReleaseDescriptor release) {return new LiveRelease(identity,release,false);}
        internal string Nonce {get{return nonce;}}
        internal bool RenewalDue {get{return HostedUtcContinuation.RenewalDue(challengeAge.Elapsed);}}
        internal void Accept(byte[] bytes,byte[] signature)
        {
            if(time!=null || challengeAge.Elapsed.TotalSeconds>=30) throw new SecurityException("UTC challenge is expired or already consumed.");
            TimeAttestation actual=TimeAttestation.Decode(bytes);
            if(actual.Installation!=identity.Installation || actual.Nonce!=nonce || actual.ReleaseSha256!=Wire.Hash(release.Encode()) ||
                !PlatformSignature.Verify(identity.TimeKey,actual.Encode(),Wire.Copy(signature,64,64))) throw new SecurityException("Actual nonce-signed UTC receipt differs.");
            time=actual;this.signature=Wire.Copy(signature,64,64);Check();
        }
        internal HostedWorkspaceTime WorkspaceTime()
        {
            Check();ulong elapsed=checked((ulong)Math.Ceiling(challengeAge.Elapsed.TotalMilliseconds*1.001)+1);
            return new HostedWorkspaceTime(time.Encode(),signature,checked(time.UpperMilliseconds+elapsed));
        }
        internal void Check()
        {
            if(time==null || challengeAge.Elapsed.TotalSeconds>=30) throw new SecurityException("Fresh nonce-signed UTC is unavailable; offline refusal.");
            // The signed interval may have been sampled anywhere after nonce
            // creation. Project the upper edge over the WHOLE challenge trip,
            // not only time since receipt. Include a conservative 1000-ppm
            // monotonic-rate margin and one millisecond quantization margin.
            ulong elapsed=checked((ulong)Math.Ceiling(challengeAge.Elapsed.TotalMilliseconds*1.001)+1);
            if(requireReleaseLifetime && (time.LowerMilliseconds<release.NotBeforeMilliseconds || checked(time.UpperMilliseconds+elapsed)>=release.ExpiresMilliseconds))
                throw new SecurityException("Release is not valid for the complete protected UTC interval.");
        }
    }
}
