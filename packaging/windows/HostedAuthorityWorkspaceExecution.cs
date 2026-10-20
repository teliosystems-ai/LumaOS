using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Threading.Tasks;

namespace Luma.Windows.Hosted
{
    internal sealed class HostedWorkspaceInvocation
    {
        private readonly string[] arguments;
        internal readonly bool Interactive;
        internal string[] Arguments {get{return (string[])arguments.Clone();}}
        internal HostedWorkspaceInvocation(AuthorityIdentity identity,HostedWorkspacePreparation prepared)
        {
            if(prepared==null) throw new ArgumentNullException("prepared");prepared.RequireIdentity(identity,identity.FirstAdminSid);
            string operation=prepared.Operation==1?"bootstrap":prepared.Operation==2?"status":"repair";
            Interactive=prepared.Operation!=2;
            arguments=new string[]{"--distribution",HostedGuestRunner.Distribution(identity,prepared.Admission),"--user","root","--exec","/usr/libexec/luma-os/luma-platform",
                "hosted-windows-workspace-"+operation+"-launch",prepared.Admission.Generation,prepared.Request.RequestSha256,prepared.Original.RequestSha256,prepared.Request.PublicHex,prepared.Original.PublicHex};
            RequireArguments(arguments);
        }
        private HostedWorkspaceInvocation(AuthorityIdentity identity,DeploymentEvent admission,string request)
        {
            if(admission==null || admission.Purpose!=5) throw new SecurityException("Workspace drain cannot borrow another resource purpose.");Wire.Bytes(request,32,true);
            arguments=new string[]{"--distribution",HostedGuestRunner.Distribution(identity,admission),"--user","root","--exec","/usr/libexec/luma-os/luma-platform","hosted-windows-workspace-drain",request};
        }
        internal static HostedWorkspaceInvocation Drain(AuthorityIdentity identity,DeploymentEvent admission,string request) {return new HostedWorkspaceInvocation(identity,admission,request);}
        internal void RequireArguments(string[] actual)
        {
            if(actual==null || actual.Length!=arguments.Length) throw new SecurityException("Workspace invocation tuple differs.");
            for(int index=0;index<actual.Length;index++) {
                if(actual[index]!=arguments[index]) throw new SecurityException("Workspace invocation changed after validation.");
                if(index>=10) {
                    if(actual[index].Length<2 || actual[index].Length>2048 || actual[index].Length%2!=0) throw new SecurityException("Workspace public request argv exceeds its exact bounded shape.");
                    foreach(char value in actual[index]) if(!(value>='0'&&value<='9') && !(value>='a'&&value<='f')) throw new SecurityException("Workspace argv contains noncanonical public hex.");
                }
            }
        }
    }
    internal static class HostedWorkspaceRunner
    {
        internal static byte[] Execute(AuthorityIdentity identity,HostedActor actor,HostedWorkspacePreparation prepared,Action<OwnedWindowsProcess> beforeResume,Action live)
        {
            byte[] result=new byte[0];live();actor.Check();HostedWorkspaceInvocation invocation=new HostedWorkspaceInvocation(identity,prepared);
            using(PinnedWsl binary=new PinnedWsl(identity.WslSha256)) {
                using(OwnedWindowsProcess controller=OwnedWindowsProcess.StartWorkspace(binary,actor,invocation,beforeResume)) {
                    Action check=delegate {actor.Check();binary.Check();live();};
                    if(!invocation.Interactive) {
                        controller.Input.Close();Stopwatch reading=Stopwatch.StartNew();
                        Task<byte[]> errors=Task.Factory.StartNew(delegate {using(MemoryStream sink=new MemoryStream()) {byte[] part=new byte[1024];while(true) {int count=controller.Error.Read(part,0,Math.Min(1024,4097-(int)sink.Length));if(count==0)return sink.ToArray();if(sink.Length+count>4096)throw new SecurityException("Workspace diagnostic output exceeded its fixed bound.");sink.Write(part,0,count);}}});
                        result=GuestComputeFrames.BoundedEnd(controller.Output,2048,check,reading,TimeSpan.FromSeconds(30));
                        controller.RequireSuccess(check,TimeSpan.FromSeconds(1));GuestComputeFrames.Await(errors,check,reading,TimeSpan.FromSeconds(30));
                        GuestWorkspaceObservation.Validate(prepared.Request,prepared.Original,result);
                    } else controller.RequireSuccess(check,TimeSpan.FromSeconds(30));
                    check();if(!controller.Exited) throw new SecurityException("Original workspace console/controller exit is unobserved.");
                }
                Drain(binary,identity,actor,prepared.Admission,prepared.Request.RequestSha256,live);
            }
            live();return result;
        }
        internal static void Drain(AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,string request,Action live)
        {using(PinnedWsl binary=new PinnedWsl(identity.WslSha256)) Drain(binary,identity,actor,admission,request,live);}
        private static void Drain(PinnedWsl binary,AuthorityIdentity identity,HostedActor actor,DeploymentEvent admission,string request,Action live)
        {
            Action check=delegate {actor.Check();binary.Check();live();};check();
            using(OwnedWindowsProcess observer=OwnedWindowsProcess.StartWorkspace(binary,actor,HostedWorkspaceInvocation.Drain(identity,admission,request),delegate(OwnedWindowsProcess process) {check();})) {
                observer.Input.Close();Stopwatch age=Stopwatch.StartNew();
                Task<byte[]> errors=Task.Factory.StartNew(delegate {return GuestComputeFrames.BoundedEnd(observer.Error,4096,check,age,TimeSpan.FromSeconds(5));});
                byte[] observation=GuestComputeFrames.BoundedEnd(observer.Output,8192,check,age,TimeSpan.FromSeconds(5));
                observer.RequireSuccess(check,TimeSpan.FromSeconds(1));GuestComputeFrames.Await(errors,check,age,TimeSpan.FromSeconds(5));ValidateDrain(observation);
                if(!observer.Exited) throw new SecurityException("Workspace request revocation/drain observer has not exited.");check();
            }
        }
        internal static void ValidateDrain(byte[] metadata)
        {
            Dictionary<string,object> fields=ObservationJson.Parse(metadata);
            string[] expected={"schema_version","profile","unit","cgroup_empty_or_absent","unit_inactive","authority_returned","job_completed"};
            if(fields.Count!=7) throw new SecurityException("Workspace drain field count differs.");foreach(string name in expected) if(!fields.ContainsKey(name)) throw new SecurityException("Workspace drain omitted a required field.");
            if(!(fields["schema_version"] is ulong) || (ulong)fields["schema_version"]!=1 || !(fields["profile"] is string) || (string)fields["profile"]!=GuestWorkspaceRequest.Profile ||
                !(fields["unit"] is string) || (string)fields["unit"]!="luma-hosted-workspace-bootstrap.service") throw new SecurityException("Workspace drain profile/unit identity differs.");
            foreach(string name in new string[]{"cgroup_empty_or_absent","unit_inactive"}) if(!(fields[name] is bool) || !(bool)fields[name]) throw new SecurityException("Workspace guest drainage remains unconfirmed.");
            foreach(string name in new string[]{"authority_returned","job_completed"}) if(!(fields[name] is bool) || (bool)fields[name]) throw new SecurityException("Workspace drain cannot claim product authority or successful workflow execution.");
        }
    }
}
