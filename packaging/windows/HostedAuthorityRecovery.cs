using System;
using System.IO;
using System.Security;

namespace Luma.Windows.Hosted
{
    // TPM observations are not UTC. Public constructors support protocol tests;
    // production obtains these fields only from fixed TPM2_ReadClock responses.
    public sealed class TpmEpoch
    {
        public ulong Time {get;private set;}public ulong Clock {get;private set;}
        public uint Reset {get;private set;}public uint Restart {get;private set;}
        public bool Safe {get;private set;}
        public TpmEpoch(ulong time,ulong clock,uint reset,uint restart,bool safe) {Time=time;Clock=clock;Reset=reset;Restart=restart;Safe=safe;}
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-tpm-epoch-v1")) {writer.U64(Time);writer.U64(Clock);writer.U32(Reset);writer.U32(Restart);writer.U8(Safe?(byte)1:(byte)0);return writer.Bytes();}}
        public static TpmEpoch Decode(byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-tpm-epoch-v1")) {ulong time=reader.U64(),clock=reader.U64();uint reset=reader.U32(),restart=reader.U32();byte safe=reader.U8();reader.End();if(safe>1) throw new InvalidDataException("TPM clock safe flag differs.");return new TpmEpoch(time,clock,reset,restart,safe==1);}
        }
        internal bool SameEpoch(TpmEpoch other) {return other!=null && Reset==other.Reset && Restart==other.Restart;}
        public void RequireResetSince(TpmEpoch previous,ulong previousBoot,ulong currentBoot) {
            // Saved sessions may survive a TPM restart/resume. A changed
            // restart counter alone is deliberately insufficient.
            if(previous==null || previousBoot==0 || currentBoot==0 || previousBoot==currentBoot || Reset<=previous.Reset)
                throw new SecurityException("Independent host boot change AND strictly advanced TPM reset count are required; restart, elapsed time and context disposal are not drain proof.");
        }
    }

    public sealed class DispatchTicket
    {
        public string RecordSha256 {get;private set;}public ulong Sequence {get;private set;}
        public string PreviousHead {get;private set;}public ulong Boot {get;private set;}
        public TpmEpoch Epoch {get;private set;}
        private readonly byte[] input,signature;
        private DispatchTicket(string record,ulong sequence,string previous,ulong boot,TpmEpoch epoch,byte[] input,byte[] signature) {
            RecordSha256=record;Sequence=sequence;PreviousHead=previous;Boot=boot;Epoch=epoch;this.input=input;this.signature=signature;
        }
        public static byte[] SigningInput(AuthorityIdentity identity,JournalEntry entry,ulong boot,TpmEpoch epoch) {
            if(identity==null || entry==null || boot==0 || epoch==null) throw new InvalidDataException("Exact pre-dispatch identity, event and kernel/TPM observations required.");
            JournalEntry.Decode(identity,entry.Bytes);
            using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-nv-dispatch-v1")) {
                writer.Fixed(Wire.HashBytes(identity.Encode()),32);writer.Fixed(Wire.Bytes(entry.RecordSha256,32,true),32);writer.U64(entry.Sequence);
                writer.Fixed(Wire.Bytes(entry.PreviousHead,32,false),32);writer.U64(boot);writer.Blob(epoch.Encode(),256);return writer.Bytes();
            }
        }
        public static DispatchTicket Signed(AuthorityIdentity identity,byte[] input,byte[] signature) {
            input=Wire.Copy(input,1,1024);signature=Wire.Copy(signature,64,64);
            if(!Luma.Windows.PlatformSignature.Verify(identity.AuthorityKey,input,signature)) throw new SecurityException("Actual dispatch ticket signature differs.");
            using(Wire.Reader reader=new Wire.Reader(input,"luma-windows-hosted-nv-dispatch-v1")) {
                if(Wire.Hex(reader.Fixed(32))!=Wire.Hash(identity.Encode())) throw new SecurityException("Dispatch ticket crosses authority installation or keys.");
                string record=Wire.Hex(reader.Fixed(32));ulong sequence=reader.U64();string previous=Wire.Hex(reader.Fixed(32));ulong boot=reader.U64();TpmEpoch epoch=TpmEpoch.Decode(reader.Blob(256));reader.End();
                Wire.Bytes(record,32,true);if(sequence<1 || sequence>1024 || boot==0) throw new SecurityException("Dispatch ticket sequence or kernel boot is invalid.");return new DispatchTicket(record,sequence,previous,boot,epoch,input,signature);
            }
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-signed-dispatch-v1")) {writer.Blob(input,1024);writer.Fixed(signature,64);return writer.Bytes();}}
        public static DispatchTicket Decode(AuthorityIdentity identity,byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-signed-dispatch-v1")) {DispatchTicket result=Signed(identity,reader.Blob(1024),reader.Fixed(64));reader.End();return result;}
        }
        public void Matches(JournalEntry entry) {if(entry==null || RecordSha256!=entry.RecordSha256 || Sequence!=entry.Sequence || PreviousHead!=entry.PreviousHead) throw new SecurityException("Dispatch ticket is not the exact abandoned event.");}
    }

    public sealed class NvAbortEvent
    {
        public DispatchTicket Abandoned {get;private set;}public ulong CurrentBoot {get;private set;}public TpmEpoch CurrentEpoch {get;private set;}
        private readonly byte[] nonce;
        public NvAbortEvent(DispatchTicket abandoned,ulong currentBoot,TpmEpoch current,byte[] nonce) {
            if(abandoned==null || current==null) throw new ArgumentNullException("abandoned");current.RequireResetSince(abandoned.Epoch,abandoned.Boot,currentBoot);
            Abandoned=abandoned;CurrentBoot=currentBoot;CurrentEpoch=current;this.nonce=Wire.Copy(nonce,32,32);if(Wire.Hex(this.nonce)==new string('0',64)) throw new SecurityException("Abort event requires a fresh nonzero action nonce.");
        }
        public byte[] Encode() {using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-nv-abort-v1")) {writer.Blob(Abandoned.Encode(),2048);writer.U64(CurrentBoot);writer.Blob(CurrentEpoch.Encode(),256);writer.Fixed(nonce,32);return writer.Bytes();}}
        public static NvAbortEvent Decode(AuthorityIdentity identity,byte[] bytes) {
            using(Wire.Reader reader=new Wire.Reader(bytes,"luma-windows-hosted-nv-abort-v1")) {NvAbortEvent result=new NvAbortEvent(DispatchTicket.Decode(identity,reader.Blob(2048)),reader.U64(),TpmEpoch.Decode(reader.Blob(256)),reader.Fixed(32));reader.End();return result;}
        }
        public void Matches(JournalEntry replacement) {
            if(replacement==null || (replacement.Kind!=JournalKind.NvWriteAborted && !(replacement.Kind==JournalKind.Commission && replacement.Sequence==1)) || replacement.Sequence!=Abandoned.Sequence || replacement.PreviousHead!=Abandoned.PreviousHead || replacement.RecordSha256==Abandoned.RecordSha256)
                throw new SecurityException("Abort is not a fresh different event at the exact previous authority head.");
            if(replacement.Kind==JournalKind.Commission) {
                using(Wire.Reader reader=new Wire.Reader(replacement.Payload,"luma-windows-hosted-commission-genesis-recovered-v1")) {reader.Blob(4096);if(!Wire.Equal(reader.Blob(2048),Encode())) throw new SecurityException("Recovered genesis substituted its exact abort proof.");reader.End();}
            } else if(!Wire.Equal(replacement.Payload,Encode())) throw new SecurityException("Abort event substituted its exact recorded proof.");
        }
    }
}
