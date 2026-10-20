using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using Luma.Windows;
using Luma.Windows.Hosted;

// Data-only codec/profile/health fixtures. No account creation, password entry,
// Linux PAM success, custody, service/distribution changes, or host qualification.
public static class LumaHostedWorkspaceFixture
{
    private static int assertions;
    private static string H(char value) {return new string(value,64);}
    private static byte[] B(string value) {return Encoding.UTF8.GetBytes(value);}
    private static void Require(bool condition) {if(!condition) throw new Exception("Workspace contract assertion failed.");assertions++;}
    private static void Refuse(Action action) {
        try {action();}catch(SecurityException) {assertions++;return;}catch(InvalidDataException) {assertions++;return;}catch(EndOfStreamException) {assertions++;return;}
        throw new Exception("Workspace contract accepted forbidden input.");
    }
    private static GuestWorkspaceRequest Request(string login,uint day)
    {return new GuestWorkspaceRequest(H('1'),H('2'),H('3'),Wire.Hash(GuestWorkspaceRequest.ExpectedProfile(H('3'))),H('5'),login,day,H('6'));}
    public static byte[][] Requests() {
        return new byte[][]{Request("alice",20746).Bytes,Request("alice-01_x",20747).Bytes,Request(new string('a',31),2932896).Bytes};
    }
    private static RequiredFile Data(string path,byte[] bytes,bool executable)
    {return new RequiredFile {Path=path,Bytes=bytes.Length,Sha256=Wire.Hash(bytes),Executable=executable};}
    private static RequiredFile[] Descriptors(out string description,out string manifest)
    {
        List<RequiredFile> files=new List<RequiredFile>();byte[] bytes=new byte[64];bytes[0]=1;
        foreach(string name in new string[]{"bin/bash","usr/libexec/luma-os/luma-platform","usr/libexec/luma-os/luma-workspace-auth-helper","usr/lib/x86_64-linux-gnu/security/pam_unix.so","lib/x86_64-linux-gnu/libc.so.6"})
            files.Add(Data(name,bytes,name=="bin/bash"||name.StartsWith("usr/libexec/",StringComparison.Ordinal)));
        files.Sort(delegate(RequiredFile a,RequiredFile b){return String.CompareOrdinal(a.Path,b.Path);});
        List<string> records=new List<string>();foreach(RequiredFile file in files) records.Add("{\"bytes\":64,\"executable\":"+(file.Executable?"true":"false")+",\"path\":\""+file.Path+"\",\"sha256\":\""+file.Sha256+"\"}");
        manifest="{\"files\":["+String.Join(",",records.ToArray())+"],\"profile\":\""+GuestWorkspaceRequest.Profile+"\",\"schema_version\":1}\n";
        description=Encoding.ASCII.GetString(GuestWorkspaceRequest.ExpectedProfile(Wire.Hash(B(manifest))));
        Dictionary<string,string> templates=new Dictionary<string,string> {
            {"passwd","root:x:0:0:Locked guest root:/root:/bin/bash\nnobody:x:65534:65534:Inert compute:/nonexistent:/bin/false\n"},{"group","root:x:0:\nnogroup:x:65534:\n"},
            {"shadow","root:!:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n"},{"gshadow","root:!::\nnogroup:!::\n"}
        };
        foreach(KeyValuePair<string,string> pair in templates) files.Add(Data("usr/share/luma-os/hosted-workspace/accounts/"+pair.Key,B(pair.Value),false));
        files.Add(Data("etc/nsswitch.conf",B("passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files\n"),false));
        files.Add(Data("etc/pam.d/luma-admin",B("# Local Linux password/account verification, not a product Admin role.\nauth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so nodelay\naccount required /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n"),false));
        files.Add(Data(GuestWorkspaceRequest.ProfilePath,B(description),false));files.Add(Data(GuestWorkspaceRequest.RuntimePath,B(manifest),false));
        return files.ToArray();
    }
    private static RequiredFile[] Rebind(RequiredFile[] original,string manifest,out string description)
    {
        description=Encoding.ASCII.GetString(GuestWorkspaceRequest.ExpectedProfile(Wire.Hash(B(manifest))));
        List<RequiredFile> files=new List<RequiredFile>();
        foreach(RequiredFile file in original) {
            if(file.Path==GuestWorkspaceRequest.ProfilePath) files.Add(Data(file.Path,B(description),false));
            else if(file.Path==GuestWorkspaceRequest.RuntimePath) files.Add(Data(file.Path,B(manifest),false));
            else files.Add(file);
        }
        return files.ToArray();
    }
    private static string Metadata(GuestWorkspaceRequest challenge,GuestWorkspaceRequest original,int count,bool complete,bool pam) {
        return "{\"schema_version\":1,\"profile\":\""+GuestWorkspaceRequest.Profile+"\",\"nonce\":\""+challenge.Nonce+"\",\"request_sha256\":\""+challenge.RequestSha256+
            "\",\"installation\":\""+challenge.Installation+"\",\"release_sha256\":\""+challenge.ReleaseSha256+"\",\"runtime_manifest_sha256\":\""+challenge.RuntimeManifestSha256+
            "\",\"profile_sha256\":\""+challenge.ProfileSha256+"\",\"actor_sid_sha256\":\""+challenge.ActorSidSha256+"\",\"account_generation\":1,\"uid\":1000,\"bootstrap_request_sha256\":\""+original.RequestSha256+
            "\",\"protected_utc_day\":"+challenge.ProtectedUtcDay+",\"utc_proof_sha256\":\""+challenge.UtcProofSha256+"\",\"password_age_within_90_days\":"+(challenge.WithinPasswordAge(original)?"true":"false")+
            ",\"applied_file_count\":"+count+",\"account_files_complete\":"+(complete?"true":"false")+",\"bootstrap_pam_verified_once\":"+(pam?"true":"false")+
            ",\"account_state_sha256\":\""+(complete?H('a'):H('0'))+"\",\"native_product_grant_bridge_available\":false,\"inference_observation\":\"not-requested\",\"authority_returned\":false,\"production_qualified\":false}";
    }
    public static int Run() {
        assertions=0;
        Require(GuestWorkspaceRequest.PurposeSeconds==30 && GuestWorkspaceRequest.CpuSeconds+GuestWorkspaceRequest.DrainSeconds==30);
        foreach(byte[] bytes in Requests()) {
            GuestWorkspaceRequest request=GuestWorkspaceRequest.Decode(bytes);
            Require(Wire.Equal(request.Bytes,bytes));Require(request.RequestSha256==Wire.Hash(bytes));
            Require(request.PublicHex==Wire.Hex(bytes));Require(bytes.Length<1024 && request.PublicHex.Length<2048);
            byte[] clone=request.Bytes;clone[0]=0;Require(request.Bytes[0]=='{');
            string text=Encoding.ASCII.GetString(bytes);Require(!text.Contains("password") && text.EndsWith("\n",StringComparison.Ordinal));
            foreach(string bad in new string[]{text.TrimEnd('\n'),text+" ",text.Replace("\"uid\":1000","\"uid\":0"),text.Replace("\"uid\":1000","\"uid\":true"),
                text.Replace("\"uid\":1000","\"uid\":1e3"),text.Replace("\"schema_version\":1","\"schema_version\":1,\"schema_version\":1"),text.Replace("\"account_generation\":1","\"account_generation\":2"),
                text.Replace("\"gid\":1000","\"extra\":false,\"gid\":1000")}) Refuse(delegate {GuestWorkspaceRequest.Decode(B(bad));});
        }
        foreach(string login in new string[]{"","root","nobody","nogroup","Alice","../alice","alice\n","a b",new string('a',32)}) {
            Require(!GuestWorkspaceRequest.CanonicalLogin(login));Refuse(delegate {Request(login,20746);});
        }
        foreach(string login in new string[]{"a","alice","alice-01_x",new string('a',31)}) Require(GuestWorkspaceRequest.CanonicalLogin(login));
        Refuse(delegate {Request("alice",0);});Refuse(delegate {Request("alice",2932897);});
        GuestWorkspaceRequest original=Request("alice",20746),challenge=Request("alice",20747);
        challenge.RequireOriginal(original,original.RequestSha256);Require(challenge.WithinPasswordAge(original));
        Refuse(delegate {original.RequireOriginal(original,original.RequestSha256);});
        Refuse(delegate {challenge.RequireOriginal(original,H('a'));});
        Refuse(delegate {Request("bob",20747).RequireOriginal(original,original.RequestSha256);});
        Refuse(delegate {Request("alice",20745).RequireOriginal(original,original.RequestSha256);});
        Require(Request("alice",20835).WithinPasswordAge(original));Require(!Request("alice",20836).WithinPasswordAge(original));
        foreach(int count in new int[]{0,1,2,3,4}) {
            GuestWorkspaceObservation observation=GuestWorkspaceObservation.Validate(challenge,original,B(Metadata(challenge,original,count,false,false)));
            Require(observation.AppliedFiles==(uint)count && !observation.AccountFilesComplete && !observation.BootstrapPamVerifiedOnce);
        }
        GuestWorkspaceObservation complete=GuestWorkspaceObservation.Validate(challenge,original,B(Metadata(challenge,original,4,true,true)));
        Require(complete.AccountFilesComplete && complete.BootstrapPamVerifiedOnce && complete.PasswordAgeWithin90Days);
        Refuse(delegate {GuestWorkspaceObservation.Validate(challenge,original,B(Metadata(challenge,original,3,true,false)));});
        Refuse(delegate {GuestWorkspaceObservation.Validate(challenge,original,B(Metadata(challenge,original,4,false,true)));});
        Refuse(delegate {GuestWorkspaceObservation.Validate(challenge,original,B(Metadata(challenge,original,5,false,false)));});
        string metadata=Metadata(challenge,original,4,true,true);
        foreach(string bad in new string[]{metadata.Replace("\"uid\":1000","\"uid\":0"),metadata.Replace("\"account_generation\":1","\"account_generation\":2"),
            metadata.Replace("\"native_product_grant_bridge_available\":false","\"native_product_grant_bridge_available\":true"),metadata.Replace("\"authority_returned\":false","\"authority_returned\":true"),
            metadata.Replace("\"production_qualified\":false","\"production_qualified\":true"),metadata.Replace("\"inference_observation\":\"not-requested\"","\"inference_observation\":\"ready\""),
            metadata.Replace("\"password_age_within_90_days\":true","\"password_age_within_90_days\":false"),metadata.Replace(challenge.Nonce,original.Nonce),
            metadata.Replace("\"schema_version\":1","\"schema_version\":1,\"extra\":false"),metadata+"{}"}) Refuse(delegate {GuestWorkspaceObservation.Validate(challenge,original,B(bad));});
        byte[] profile=GuestWorkspaceRequest.ExpectedProfile(H('3'));
        Require(Encoding.ASCII.GetString(profile).Contains("\"schema_version\":3"));
        Require(Encoding.ASCII.GetString(profile).Contains("\"default_uid\":65534,\"drain_seconds\":5"));
        Require(Wire.Equal(profile,PackageInspector.WorkspaceProfile(H('3'))));
        string description,manifest;RequiredFile[] files=Descriptors(out description,out manifest);
        PackageInspector.ValidateWorkspaceDescriptors(description,manifest,files);Require(true);
        Refuse(delegate {PackageInspector.WorkspaceProfile(H('0'));});
        foreach(string bad in new string[]{description.Replace("\"default_uid\":65534","\"default_uid\":1000"),description.Replace("\"password_max_age_days\":90","\"password_max_age_days\":99999"),description+" "})
            Refuse(delegate {PackageInspector.ValidateWorkspaceDescriptors(bad,manifest,files);});
        foreach(string bad in new string[]{manifest.Replace("\"executable\":true","\"executable\":false"),manifest.Replace("bin/bash","usr/bin/unreviewed"),
            manifest.Replace("security/pam_unix.so","security/pam_permit.so"),manifest.Replace("\"schema_version\":1","\"schema_version\":1,\"extra\":false"),manifest+" "})
        {
            string rebound;RequiredFile[] bound=Rebind(files,bad,out rebound);
            Refuse(delegate {PackageInspector.ValidateWorkspaceDescriptors(rebound,bad,bound);});
        }
        foreach(string missing in new string[]{"usr/libexec/luma-os/luma-workspace-auth-helper","etc/pam.d/luma-admin","etc/nsswitch.conf","usr/share/luma-os/hosted-workspace/accounts/shadow"}) {
            List<RequiredFile> reduced=new List<RequiredFile>();foreach(RequiredFile file in files) if(file.Path!=missing) reduced.Add(file);
            Refuse(delegate {PackageInspector.ValidateWorkspaceDescriptors(description,manifest,reduced.ToArray());});
        }
        return assertions;
    }
}
