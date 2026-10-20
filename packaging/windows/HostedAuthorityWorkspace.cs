using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security;
using System.Text;

namespace Luma.Windows.Hosted
{
    internal sealed class HostedWorkspaceTime
    {
        internal readonly byte[] Proof,Signature;internal readonly uint Day;
        internal HostedWorkspaceTime(byte[] proof,byte[] signature,ulong conservativeUpper)
        {
            Proof=Wire.Copy(proof,1,512);Signature=Wire.Copy(signature,64,64);TimeAttestation actual=TimeAttestation.Decode(Proof);
            ulong lower=actual.LowerMilliseconds/86400000UL,upper=conservativeUpper/86400000UL;
            if(lower<1 || lower!=upper || upper>2932896 || conservativeUpper<actual.UpperMilliseconds)
                throw new SecurityException("Workspace aging requires one unambiguous protected UTC day; midnight uncertainty refuses.");
            Day=(uint)lower;
        }
    }
    // Pure, separate first-account wire contract. Neither construction nor a
    // matching guest observation grants Windows custody or Linux PAM authority.
    public sealed class GuestWorkspaceRequest
    {
        public const string Profile="luma-windows-hosted-workspace-v1";
        public const string ProfilePath="usr/share/luma-os/hosted-workspace.json";
        public const string RuntimePath="usr/share/luma-os/hosted-workspace-runtime.json";
        public const int PurposeSeconds=30,CpuSeconds=25,DrainSeconds=5,MaximumEncoded=32768;
        public string Installation {get;private set;}
        public string ReleaseSha256 {get;private set;}
        public string RuntimeManifestSha256 {get;private set;}
        public string ProfileSha256 {get;private set;}
        public string ActorSidSha256 {get;private set;}
        public string Login {get;private set;}
        public string Nonce {get;private set;}
        public uint ProtectedUtcDay {get;private set;}
        public string UtcProofSha256 {get;private set;}
        private readonly byte[] encoded;
        public byte[] Bytes {get{return (byte[])encoded.Clone();}}
        public string RequestSha256 {get{return Wire.Hash(encoded);}}
        public string PublicHex {get{return Wire.Hex(encoded);}}
        public GuestWorkspaceRequest(string installation,string release,string runtime,string profile,string actor,string login,uint day,string utc)
            :this(installation,release,runtime,profile,actor,login,day,utc,Wire.Hex(Wire.Random(32))) {}
        internal static GuestWorkspaceRequest Challenge(string installation,string release,string runtime,string profile,string actor,string login,uint day,string utc,string nonce)
        {return new GuestWorkspaceRequest(installation,release,runtime,profile,actor,login,day,utc,nonce);}
        private GuestWorkspaceRequest(string installation,string release,string runtime,string profile,string actor,string login,uint day,string utc,string nonce)
        {
            foreach(string hash in new string[]{installation,release,runtime,profile,actor,utc,nonce}) Wire.Bytes(hash,32,true);
            if(!CanonicalLogin(login) || day<1 || day>2932896) throw new SecurityException("New workspace account or protected UTC day differs.");
            Installation=installation;ReleaseSha256=release;RuntimeManifestSha256=runtime;ProfileSha256=profile;
            ActorSidSha256=actor;Login=login;ProtectedUtcDay=day;UtcProofSha256=utc;Nonce=nonce;
            encoded=Encoding.ASCII.GetBytes("{\"account_generation\":1,\"actor_sid_sha256\":"+Q(actor)+",\"gid\":1000,\"installation\":"+Q(installation)+
                ",\"login\":"+Q(login)+",\"nonce\":"+Q(nonce)+",\"profile\":"+Q(Profile)+",\"profile_sha256\":"+Q(profile)+
                ",\"protected_utc_day\":"+day.ToString(CultureInfo.InvariantCulture)+",\"release_sha256\":"+Q(release)+",\"runtime_manifest_sha256\":"+Q(runtime)+
                ",\"schema_version\":1,\"uid\":1000,\"utc_proof_sha256\":"+Q(utc)+"}\n");
            if(encoded.Length>MaximumEncoded) throw new SecurityException("Workspace public request exceeds its fixed bound.");
        }
        private static string Q(string value) {return GuestComputeRequest.Quote(value);}
        public static bool CanonicalLogin(string value)
        {
            if(String.IsNullOrEmpty(value) || value.Length>31 || value=="root" || value=="nobody" || value=="nogroup" || value[0]<'a' || value[0]>'z') return false;
            foreach(char part in value) if(!(part>='a'&&part<='z') && !(part>='0'&&part<='9') && part!='_' && part!='-') return false;
            return true;
        }
        public static GuestWorkspaceRequest Decode(byte[] bytes)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(Wire.Copy(bytes,1,MaximumEncoded),MaximumEncoded);
            string[] text={"profile","nonce","installation","release_sha256","runtime_manifest_sha256","profile_sha256","actor_sid_sha256","login","utc_proof_sha256"};
            string[] numbers={"schema_version","uid","gid","account_generation","protected_utc_day"};
            if(fields.Count!=14) throw new SecurityException("Workspace request has missing or unknown fields.");
            foreach(string key in text) if(!fields.ContainsKey(key) || !(fields[key] is string)) throw new SecurityException("Workspace request string type differs.");
            foreach(string key in numbers) if(!fields.ContainsKey(key) || !(fields[key] is ulong)) throw new SecurityException("Workspace request integer type differs.");
            if((string)fields["profile"]!=Profile || (ulong)fields["schema_version"]!=1 || (ulong)fields["uid"]!=1000 || (ulong)fields["gid"]!=1000 ||
                (ulong)fields["account_generation"]!=1 || (ulong)fields["protected_utc_day"]>2932896) throw new SecurityException("Workspace request changes the exact one-account generation.");
            GuestWorkspaceRequest result=new GuestWorkspaceRequest((string)fields["installation"],(string)fields["release_sha256"],(string)fields["runtime_manifest_sha256"],
                (string)fields["profile_sha256"],(string)fields["actor_sid_sha256"],(string)fields["login"],(uint)(ulong)fields["protected_utc_day"],(string)fields["utc_proof_sha256"],(string)fields["nonce"]);
            if(!Wire.Equal(result.encoded,bytes)) throw new SecurityException("Workspace request must be exact sorted ASCII JSON plus one LF.");
            return result;
        }
        public void RequireOriginal(GuestWorkspaceRequest original,string originalSha)
        {
            Wire.Bytes(originalSha,32,true);
            if(original==null || original.RequestSha256!=originalSha || Nonce==original.Nonce || Installation!=original.Installation || ReleaseSha256!=original.ReleaseSha256 ||
                RuntimeManifestSha256!=original.RuntimeManifestSha256 || ProfileSha256!=original.ProfileSha256 || ActorSidSha256!=original.ActorSidSha256 || Login!=original.Login || ProtectedUtcDay<original.ProtectedUtcDay)
                throw new SecurityException("Fresh workspace challenge cannot adopt another actor/account/release or roll protected UTC backward.");
        }
        public bool WithinPasswordAge(GuestWorkspaceRequest original)
        {RequireOriginal(original,original==null?new string('0',64):original.RequestSha256);return ProtectedUtcDay-original.ProtectedUtcDay<90;}
        public static byte[] ExpectedProfile(string runtime)
        {return Luma.Windows.PackageInspector.WorkspaceProfile(runtime);}
        public void RequireRelease(ReleaseDescriptor release)
        {
            if(release==null || release.Environment!="lab" || Wire.Hash(release.Encode())!=ReleaseSha256) throw new SecurityException("Workspace request must name its exact signed active laboratory release, not production qualification.");
            Dictionary<string,Luma.Windows.RequiredFile> files=new Dictionary<string,Luma.Windows.RequiredFile>(StringComparer.Ordinal);
            foreach(Luma.Windows.RequiredFile file in release.RequiredFiles) files.Add(file.Path,file);
            string[] required={ProfilePath,RuntimePath,"usr/libexec/luma-os/luma-platform","usr/libexec/luma-os/luma-workspace-auth-helper","bin/bash",
                "usr/lib/x86_64-linux-gnu/security/pam_unix.so","etc/pam.d/luma-admin","etc/nsswitch.conf","etc/apparmor.d/luma-hosted-workspace-bootstrap",
                "etc/systemd/system/luma-hosted-workspace-confinement.service","etc/systemd/system/multi-user.target.wants/luma-hosted-workspace-confinement.service",
                "usr/share/luma-os/hosted-workspace/accounts/passwd","usr/share/luma-os/hosted-workspace/accounts/group","usr/share/luma-os/hosted-workspace/accounts/shadow","usr/share/luma-os/hosted-workspace/accounts/gshadow"};
            foreach(string path in required) if(!files.ContainsKey(path)) throw new SecurityException("Active release omits the separate workspace account/PAM/runtime closure.");
            byte[] expected=ExpectedProfile(RuntimeManifestSha256);
            if(ProfileSha256!=Wire.Hash(expected) || files[ProfilePath].Sha256!=ProfileSha256 || files[ProfilePath].Bytes!=expected.Length || files[ProfilePath].Executable ||
                files[RuntimePath].Sha256!=RuntimeManifestSha256 || files[RuntimePath].Bytes<1 || files[RuntimePath].Bytes>32768 || files[RuntimePath].Executable)
                throw new SecurityException("Workspace publisher profile/runtime differs from the fixed reviewed schema3 policy.");
            foreach(string path in new string[]{"usr/libexec/luma-os/luma-platform","usr/libexec/luma-os/luma-workspace-auth-helper","bin/bash"})
                if(!files[path].Executable || files[path].Bytes<64 || files[path].Bytes>64*1024*1024) throw new SecurityException("Workspace actual worker/helper/login shell is not a bounded executable.");
        }
    }

    public sealed class GuestWorkspaceObservation
    {
        public uint AppliedFiles {get;private set;}
        public bool AccountFilesComplete {get;private set;}
        public bool BootstrapPamVerifiedOnce {get;private set;}
        public bool PasswordAgeWithin90Days {get;private set;}
        internal string AccountStateSha256 {get;private set;}
        public static GuestWorkspaceObservation Validate(GuestWorkspaceRequest challenge,GuestWorkspaceRequest original,byte[] metadata)
        {
            if(challenge==null || original==null) throw new ArgumentNullException("workspace challenge");
            challenge.RequireOriginal(original,original.RequestSha256);
            Dictionary<string,object> fields=ObservationJson.Parse(metadata);
            string[] names={"schema_version","profile","nonce","request_sha256","installation","release_sha256","runtime_manifest_sha256","profile_sha256","actor_sid_sha256",
                "account_generation","uid","bootstrap_request_sha256","protected_utc_day","utc_proof_sha256","password_age_within_90_days","applied_file_count","account_files_complete",
                "bootstrap_pam_verified_once","account_state_sha256","native_product_grant_bridge_available","inference_observation","authority_returned","production_qualified"};
            if(fields.Count!=names.Length) throw new SecurityException("Workspace health observation fields differ.");
            foreach(string key in names) if(!fields.ContainsKey(key)) throw new SecurityException("Workspace health observation omitted a field.");
            Func<string,string> text=delegate(string key) {if(!(fields[key] is string)) throw new SecurityException("Workspace health text type differs.");return (string)fields[key];};
            Func<string,ulong> number=delegate(string key) {if(!(fields[key] is ulong)) throw new SecurityException("Workspace health integer type differs.");return (ulong)fields[key];};
            Func<string,bool> boolean=delegate(string key) {if(!(fields[key] is bool)) throw new SecurityException("Workspace health boolean type differs.");return (bool)fields[key];};
            if(number("schema_version")!=1 || text("profile")!=GuestWorkspaceRequest.Profile || text("nonce")!=challenge.Nonce || text("request_sha256")!=challenge.RequestSha256 ||
                text("installation")!=challenge.Installation || text("release_sha256")!=challenge.ReleaseSha256 || text("runtime_manifest_sha256")!=challenge.RuntimeManifestSha256 ||
                text("profile_sha256")!=challenge.ProfileSha256 || text("actor_sid_sha256")!=challenge.ActorSidSha256 || text("bootstrap_request_sha256")!=original.RequestSha256 ||
                number("account_generation")!=1 || number("uid")!=1000 || number("protected_utc_day")!=challenge.ProtectedUtcDay || text("utc_proof_sha256")!=challenge.UtcProofSha256 ||
                number("applied_file_count")>4 || text("inference_observation")!="not-requested" || boolean("native_product_grant_bridge_available") || boolean("authority_returned") || boolean("production_qualified"))
                throw new SecurityException("Workspace observation substituted its actor/account/release/UTC/challenge or claimed unavailable authority.");
            bool complete=boolean("account_files_complete"),pam=boolean("bootstrap_pam_verified_once"),age=boolean("password_age_within_90_days");
            string witness=text("account_state_sha256");Wire.Bytes(witness,32,false);
            if((complete || pam) && number("applied_file_count")!=4 || pam && !complete || age!=challenge.WithinPasswordAge(original))
                throw new SecurityException("Workspace health completion/PAM/aging fields contradict exact account state.");
            if(complete==(witness==new string('0',64))) throw new SecurityException("Workspace private state witness contradicts completion.");
            return new GuestWorkspaceObservation {AppliedFiles=(uint)number("applied_file_count"),AccountFilesComplete=complete,BootstrapPamVerifiedOnce=pam,PasswordAgeWithin90Days=age,AccountStateSha256=witness};
        }
    }
}
