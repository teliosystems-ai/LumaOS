using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security;

namespace Luma.Windows.Hosted
{
    internal sealed class HostedRuntimeInputs : IDisposable
    {
        internal readonly RuntimeUpdate Update;internal readonly byte[] Description,Signature;
        private readonly List<PlatformInputLease> leases=new List<PlatformInputLease>();private readonly List<FileStream> files=new List<FileStream>();
        private string slot;private int source;
        internal HostedRuntimeInputs(string[] arguments,bool transfer) {
            using(PlatformInputLease descriptor=PlatformInputLease.Acquire(arguments[1])) using(PlatformInputLease signature=PlatformInputLease.Acquire(arguments[2])) {Description=descriptor.Capture(1,2048);Signature=signature.Capture(64,64);Update=RuntimeUpdate.Decode(Description);}
            if(transfer) {
                try {string directory=Path.GetFullPath(arguments[3]);if(directory.Length<3 || !Char.IsLetter(directory[0]) || directory[1]!=':' || directory[2]!='\\' || directory!=arguments[3].TrimEnd('\\')) throw new SecurityException("Original-client bundle directory must be exact canonical local storage.");
                    foreach(RuntimeComponent component in Update.Bundle.Components) {string path=Path.Combine(directory,component.Name);PlatformInputLease lease=PlatformInputLease.Acquire(path);leases.Add(lease);FileStream input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);files.Add(input);if(input.Length!=component.Bytes) throw new SecurityException("Selected runtime source length differs from the exact signed bundle.");lease.Check();}
                } catch {Dispose();throw;}
            }
        }
        internal void Reviewed(byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-review-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(Description) || !Wire.Equal(reader.Fixed(64),Signature)) throw new SecurityException("Runtime review changed the selected descriptor/signature.");
                slot=Wire.Hex(reader.Fixed(32));Wire.Bytes(slot,32,true);Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);reader.End();
            }
        }
        internal byte[] Part(byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-runtime-next-v1")) {
                if(files.Count!=4 || slot==null || Wire.Hex(reader.Fixed(32))!=slot) throw new SecurityException("Runtime transfer lacks the exact original-client reviewed generation.");
                int index=reader.U8();ulong offset=reader.U64();uint count=reader.U32();reader.End();if(index!=source || index>=4 || offset!=(ulong)files[index].Position || count!=(ulong)Math.Min(32768,Update.Bundle.Components[index].Bytes-(long)offset) || count<1) throw new SecurityException("Runtime transfer source, offset, length or ordering changed.");
                leases[index].Check();byte[] part=new byte[count];int at=0;while(at<part.Length) {int got=files[index].Read(part,at,part.Length-at);if(got==0) throw new EndOfStreamException("Original runtime source truncated.");at+=got;}leases[index].Check();if(files[index].Position==files[index].Length) source++;
                using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-runtime-part-v1")) {writer.Fixed(Wire.Bytes(slot,32,true),32);writer.U8((byte)index);writer.U64(offset);writer.Blob(part,32768);return writer.Bytes();}
            }
        }
        public void Dispose() {foreach(FileStream file in files) file.Dispose();files.Clear();foreach(PlatformInputLease lease in leases) lease.Dispose();leases.Clear();}
    }
    internal static partial class HostedCoordinator
    {
        private sealed class RuntimeUtcLease
        {
            private readonly NamedPipeServerStream pipe;private readonly AuthorityIdentity identity;private readonly string endpoint;private readonly RuntimeUpdate update;private readonly Action original;private readonly bool lifetime;
            private LiveUtcWindow current;private Stopwatch since;private readonly object sync=new object();
            internal RuntimeUtcLease(NamedPipeServerStream pipe,AuthorityIdentity identity,string endpoint,RuntimeUpdate update,Action original,bool lifetime) {this.pipe=pipe;this.identity=identity;this.endpoint=endpoint;this.update=update;this.original=original;this.lifetime=lifetime;}
            internal void Check() {lock(sync) {original();if(current==null || since.Elapsed.TotalSeconds>=10) {current=RuntimeTime(pipe,identity,endpoint,update,original,lifetime);since=Stopwatch.StartNew();}current.Check();original();}}
            internal void CheckObserved() {lock(sync) {original();if(current==null) throw new SecurityException("Runtime UTC has no observed proof.");current.Check();original();}}
            internal byte[][] Snapshot() {lock(sync) {Check();return new byte[][]{current.Proof,current.Signature};}}
        }
        private static LiveUtcWindow RuntimeTime(NamedPipeServerStream pipe,AuthorityIdentity identity,string endpoint,RuntimeUpdate update,Action original,bool lifetime) {
            original();LiveUtcWindow live=new LiveUtcWindow(identity,Wire.Hash(update.Encode()),lifetime?update.NotBefore:1,lifetime?update.Expires:4102444800000UL);byte[] challenge;
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-utc-challenge-v1")) {writer.Fixed(Wire.Bytes(identity.Installation,32,true),32);writer.Fixed(Wire.Bytes(live.Nonce,32,true),32);writer.Fixed(Wire.HashBytes(update.Encode()),32);challenge=writer.Bytes();}
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-time-relay-v1")) {writer.Text(endpoint,2048);writer.Blob(challenge,1024);Reply(pipe,"utc-challenge",writer.Bytes(),original);}
            byte[] delivery=HostedPipe.Read(pipe,original,TimeSpan.FromSeconds(20));using(Wire.Reader reader=new Wire.Reader(delivery,"luma-windows-hosted-utc-delivery-v1")) {live.Accept(reader.Blob(8192),reader.Fixed(64));reader.End();}original();return live;
        }
        private static void RuntimeCommand(NamedPipeServerStream pipe,HostedActor actor,Wire.Reader request,Action running,string operation) {
            byte[] bytes=request.Blob(2048),signature=request.Fixed(64);request.End();RuntimeUpdate update=RuntimeUpdate.Decode(bytes);bool prepare=operation=="runtime-prepare",cancel=operation=="runtime-cancel",finalize=operation=="runtime-finalize";
            Stopwatch age=Stopwatch.StartNew();Action original=delegate {running();actor.Check();if(age.Elapsed.TotalSeconds>=(prepare?1800:30)) throw new SecurityException("Exact finite runtime maintenance purpose expired.");};
            using(NativeAuthority authority=new NativeAuthority("host-deployment",actor,prepare?RuntimeAccess.Prepare:cancel?RuntimeAccess.Inspect:RuntimeAccess.Continue)) {
                JournalHistory history=authority.Journal.Read(original);history.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedRuntimeState state=authority.Runtime;
                if(authority.Trust.TimeRevoked) throw new SecurityException("Runtime maintenance requires fresh currently non-revoked independent UTC.");
                AuthorityIdentity current=cancel?authority.Trust.CurrentIdentity:authority.Trust.ForRelease();if(!cancel) update.Verify(current,signature);
                if(prepare) {
                    if(state.Pending!=null || update.Generation!=checked(state.Generation+1) || update.Previous!=state.SourceSha256 || update.Bundle.Sha256==state.Current.Sha256 && update.WslSha256==state.WslSha256) throw new SecurityException("Runtime preparation is concurrent, stale or unchanged.");
                } else if(state.Pending==null || !Wire.Equal(state.Pending.Update.Encode(),bytes)) throw new SecurityException("Runtime maintenance changed its exact committed prepared descriptor.");
                string slot=prepare?Wire.Hex(Wire.Random(32)):state.Pending.Slot;
                using(Wire.Writer review=new Wire.Writer("luma-windows-hosted-runtime-review-v1")) {
                    review.Fixed(Wire.HashBytes(bytes),32);review.Fixed(signature,64);review.Fixed(Wire.Bytes(slot,32,true),32);review.Fixed(Wire.Bytes(history.Head,32,true),32);
                    Review(pipe,operation,review.Bytes(),"Exact "+operation+"; runtime generation "+update.Generation+"\nDescriptor SHA256: "+Wire.Hash(bytes)+"\nBundle SHA256: "+update.Bundle.Sha256+"\nWSL SHA256: "+update.WslSha256+
                        "\nRetained current executable: "+HostedRuntimeFiles.Executable(state.Slot)+"\nPrepared executable: "+HostedRuntimeFiles.Executable(slot)+
                        "\nNever overwrite the running bundle, auto-restart a service, alter a WSL distribution, infer activation from a configured ImagePath, or claim production qualification. Explicit SCM stop/start and a fresh runtime-finalize action are required.",original);
                }
                RuntimeUtcLease utc=new RuntimeUtcLease(pipe,current,authority.Trust.Endpoint,update,original,!cancel);Action check=delegate {original();authority.State.Check();utc.Check();};check();
                if(prepare) {
                    byte[][] observation=utc.Snapshot();RuntimePreparation preparation=new RuntimePreparation(update,slot,signature,observation[0],observation[1]);preparation.Validate(current);authority.Journal.Append(JournalKind.RuntimePrepared,actor.Sid,preparation.Encode(),check);
                    state=HostedRuntimeState.Replay(authority.Identity,authority.Intent.Baseline,HostedTrustState.Replay(authority.Identity,authority.Intent,authority.Journal.Read(check),check),authority.Journal.Read(check),check);
                    HostedRuntimeFiles.Stage(preparation,delegate(int index,long offset) {
                        check();Action observed=delegate {original();authority.State.Check();utc.CheckObserved();};
                        using(Wire.Writer next=new Wire.Writer("luma-windows-hosted-runtime-next-v1")) {next.Fixed(Wire.Bytes(slot,32,true),32);next.U8((byte)index);next.U64((ulong)offset);next.U32((uint)Math.Min(32768,update.Bundle.Components[index].Bytes-offset));Reply(pipe,"runtime-next",next.Bytes(),observed);}
                        byte[] part=HostedPipe.Read(pipe,observed,TimeSpan.FromSeconds(30));using(Wire.Reader reader=new Wire.Reader(part,"luma-windows-hosted-runtime-part-v1")) {if(Wire.Hex(reader.Fixed(32))!=slot || reader.U8()!=index || reader.U64()!=(ulong)offset) throw new SecurityException("Original-client runtime transfer generation/source/offset changed.");byte[] data=reader.Blob(32768);reader.End();return data;}
                    },check);
                }
                if(cancel) {
                    using(InstalledRuntimeLease retained=new InstalledRuntimeLease(state.Slot,state.Current,check)) {retained.Check();HostedRuntimeScm.Switch(state,false,check);retained.Check();}
                    byte[][] observation=utc.Snapshot();RuntimeCompletion completion=new RuntimeCompletion(Wire.Hash(state.Pending.Encode()),true,new byte[64],observation[0],observation[1]);completion.Validate(state.Pending,current,false);authority.Journal.Append(JournalKind.RuntimeCancelled,actor.Sid,completion.Encode(),check);
                } else {
                    using(InstalledRuntimeLease staged=new InstalledRuntimeLease(state.Pending.Slot,state.Pending.Update.Bundle,check)) {
                    staged.Check();
                    if(FileHash(Path.Combine(System.Environment.SystemDirectory,"wsl.exe"))!=update.WslSha256) throw new SecurityException("Actual Microsoft WSL dependency differs from the publisher-approved target; prepared state is retained.");
                    if(finalize) {
                        if(!String.Equals(HostedRuntimeFiles.Running,HostedRuntimeFiles.Executable(state.Pending.Slot),StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Post-restart finalize must run in the actual exact newly staged service image, not the old controller.");
                        HostedRuntimeScm.Require(state,true,check);byte[][] observation=utc.Snapshot();RuntimeCompletion completion=new RuntimeCompletion(Wire.Hash(state.Pending.Encode()),false,signature,observation[0],observation[1]);completion.Validate(state.Pending,current,true);authority.Journal.Append(JournalKind.RuntimeActivated,actor.Sid,completion.Encode(),check);
                    } else HostedRuntimeScm.Switch(state,true,check);
                    staged.Check();}
                }
                JournalHistory completed=authority.Journal.Read(check);completed.Reconcile(authority.Identity,null,authority.Nv.ReadHead());HostedTrustState trust=HostedTrustState.Replay(authority.Identity,authority.Intent,completed,check);HostedRuntimeState verified=HostedRuntimeState.Replay(authority.Identity,authority.Intent.Baseline,trust,completed,check);
                if((cancel || finalize)?verified.Pending!=null:verified.Pending==null) throw new SecurityException("Actual runtime transition did not reconstruct from genuine NV-backed history.");
                using(Wire.Writer result=new Wire.Writer("luma-windows-hosted-runtime-result-v1")) {result.Fixed(Wire.HashBytes(bytes),32);result.Fixed(Wire.Bytes(slot,32,true),32);result.U8(cancel?(byte)2:finalize?(byte)1:(byte)0);result.U64(verified.Generation);result.Fixed(Wire.Bytes(verified.SourceSha256,32,true),32);result.U8(0);Reply(pipe,"runtime-observed",result.Bytes(),check);}
            }
        }
    }
}
