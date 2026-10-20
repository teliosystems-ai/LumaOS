using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using Luma.Windows;

namespace Luma.Windows.Hosted
{
    // Admission is bound to the actual original actor and held private NTFS
    // namespace, not to a preflight JSON file or an enterprise-approval flag.
    internal sealed class HostedProtectionLease
    {
        private readonly PrivateState state;private readonly HostedActor actor;private readonly Action original;
        private readonly HostProtectionSamples samples;private readonly string volume;private readonly uint serial;
        internal HostedProtectionLease(PrivateState state,HostedActor actor,Action original)
        {
            if(state==null || actor==null || original==null) throw new ArgumentNullException("protection boundary");
            this.state=state;this.actor=actor;this.original=original;Stopwatch clock=Stopwatch.StartNew();
            samples=new HostProtectionSamples(delegate {return WindowsHostProtection.Observe(state.DirectoryPath,actor.Token.DangerousGetHandle());},delegate {return clock.ElapsedMilliseconds;});
            original();actor.Check();state.Check();HostProtectionObservation first=samples.Read(true);first.Volume.RequireProtected();first.Management.RequireLocalChecks(actor.Sid);
            volume=first.Volume.Volume;serial=first.Volume.Serial;CheckFresh();
        }
        private void Check(bool fresh)
        {
            original();actor.Check();state.Check();HostProtectionObservation current=samples.Read(fresh);
            current.RequireAdmitted(volume,serial,actor.Sid);
            state.Check();actor.Check();original();
        }
        internal void Check() {Check(false);}
        internal void CheckFresh() {Check(true);}
        internal static void BeforeCommission(HostedActor actor,Action original)
        {
            original();actor.Check();string path=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            HostProtectionObservation current=WindowsHostProtection.Observe(path,actor.Token.DangerousGetHandle());
            current.Volume.RequireProtected();current.Management.RequireLocalChecks(actor.Sid);actor.Check();original();
        }
    }
}
