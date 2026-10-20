using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Security;
using System.Threading.Tasks;

namespace Luma.Windows.Hosted
{
    public static class HostedTimeEndpoint
    {
        public static string Validate(string endpoint)
        {
            Uri uri;
            if(endpoint==null || endpoint.Length<10 || endpoint.Length>2048 || !Uri.TryCreate(endpoint,UriKind.Absolute,out uri) ||
                uri.Scheme!="https" || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0 || uri.Query.Length!=0 || uri.Host.Length==0 ||
                uri.AbsoluteUri!=endpoint || uri.IsDefaultPort && uri.Port!=443)
                throw new SecurityException("Commissioned UTC endpoint must be an exact canonical HTTPS URL without credentials, fragment or query.");
            return endpoint;
        }
        internal static void Deliver(PipeStream pipe,byte[] payload,string expectedSource,Action check)
        {
            string endpoint;byte[] challenge;
            using(Wire.Reader reader=new Wire.Reader(payload,"luma-windows-hosted-time-relay-v1")) {endpoint=Validate(reader.Text(2048));challenge=reader.Blob(1024);reader.End();}
            using(Wire.Reader reader=new Wire.Reader(challenge,"luma-windows-hosted-utc-challenge-v1")) {
                Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);Wire.Bytes(Wire.Hex(reader.Fixed(32)),32,true);string source=Wire.Hex(reader.Fixed(32));Wire.Bytes(source,32,true);reader.End();
                if(source!=expectedSource) throw new SecurityException("UTC relay changed the exact original-client selected source.");
            }
            HttpWebRequest request=(HttpWebRequest)WebRequest.Create(endpoint);request.Method="POST";request.ContentType="application/octet-stream";
            request.Accept="application/octet-stream";request.AllowAutoRedirect=false;request.UseDefaultCredentials=false;request.Credentials=null;request.Proxy=null;
            request.KeepAlive=false;request.AutomaticDecompression=DecompressionMethods.None;request.Timeout=10000;request.ReadWriteTimeout=10000;
            request.ContentLength=challenge.Length;Stopwatch deadline=Stopwatch.StartNew();TimeSpan maximum=TimeSpan.FromSeconds(15);
            try {
                using(Stream upload=GuestComputeFrames.Await(request.GetRequestStreamAsync(),check,deadline,maximum)) {
                    GuestComputeFrames.Await(Task.Factory.StartNew(delegate {upload.Write(challenge,0,challenge.Length);upload.Flush();return true;}),check,deadline,maximum);
                }
                byte[] delivery;
                using(HttpWebResponse response=(HttpWebResponse)GuestComputeFrames.Await(request.GetResponseAsync(),check,deadline,maximum)) {
                    if(response.StatusCode!=HttpStatusCode.OK || response.ContentLength>12288 || response.ContentLength==0 ||
                        response.ContentType!="application/octet-stream") throw new SecurityException("Protected UTC publisher response type/status/size differs.");
                    using(Stream input=response.GetResponseStream()) delivery=GuestComputeFrames.BoundedEnd(input,12288,check,deadline,maximum);
                }
                // HTTPS is a transport only. The actual service validates every
                // nonce, interval, installation, release and P256 signature.
                HostedPipe.Write(pipe,delivery,check,TimeSpan.FromSeconds(5));
            } finally {request.Abort();}
        }
    }

    internal sealed class HostedReleaseLease
    {
        private readonly PipeStream pipe;private readonly NativeAuthority authority;private readonly ReleaseDescriptor release;private readonly Action original;
        private readonly bool requireLifetime;private readonly AuthorityIdentity verifier;
        private readonly object sync=new object();
        private LiveRelease current;
        internal HostedReleaseLease(PipeStream pipe,NativeAuthority authority,ReleaseDescriptor release,byte[] signature,Action original)
            :this(pipe,authority,release,signature,original,true,authority.Trust.ForRelease()) {}
        private HostedReleaseLease(PipeStream pipe,NativeAuthority authority,ReleaseDescriptor release,byte[] signature,Action original,bool lifetime,AuthorityIdentity verifier)
        {
            this.pipe=pipe;this.authority=authority;this.release=release;this.original=original;
            release.Verify(verifier,signature);requireLifetime=lifetime;this.verifier=verifier;
        }
        internal static HostedReleaseLease ForAbandonment(PipeStream pipe,NativeAuthority authority,ReleaseDescriptor release,byte[] signature,Action original,AuthorityIdentity verifier)
        {return new HostedReleaseLease(pipe,authority,release,signature,original,false,verifier);}
        internal void Check()
        {
            lock(sync) {
            original();if(current==null || current.RenewalDue) {
                LiveRelease previous=current;
                Action renewal=HostedUtcContinuation.Require(original,previous==null?null:new Action(previous.Check));renewal();
                LiveRelease next=requireLifetime?new LiveRelease(verifier,release):LiveRelease.ForAbandonment(verifier,release);byte[] challenge;
                using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-utc-challenge-v1")) {
                    writer.Fixed(Wire.Bytes(authority.Identity.Installation,32,true),32);writer.Fixed(Wire.Bytes(next.Nonce,32,true),32);writer.Fixed(Wire.HashBytes(release.Encode()),32);challenge=writer.Bytes();
                }
                using(Wire.Writer writer=new Wire.Writer("luma-windows-hosted-time-relay-v1")) {
                    writer.Text(authority.Trust.Endpoint,2048);writer.Blob(challenge,1024);HostedCoordinator.Reply(pipe,"utc-challenge",writer.Bytes(),renewal);
                }
                byte[] delivery=HostedPipe.Read(pipe,renewal,TimeSpan.FromSeconds(20));
                using(Wire.Reader reader=new Wire.Reader(delivery,"luma-windows-hosted-utc-delivery-v1")) {byte[] proof=reader.Blob(8192),signature=reader.Fixed(64);reader.End();renewal();next.Accept(proof,signature);}
                renewal();current=next;
            }
            current.Check();original();
            }
        }
        internal void CheckObserved()
        {
            lock(sync) {
            // During a manual confirmation the original client is intentionally
            // not servicing relay requests. Do not insert a second protocol
            // dialogue into its pending confirmation; expiry simply refuses.
            original();if(current==null) throw new SecurityException("Protected UTC has not been observed.");current.Check();original();
            }
        }
    }

    // Pure continuation composition, not a clock or authority provider. During
    // renewal the actual previous nonce-signed proof must remain valid until
    // the next proof is accepted; a slow/offline relay cannot bridge a gap.
    public static class HostedUtcContinuation
    {
        public static bool RenewalDue(TimeSpan wholeNonceAge)
        {if(wholeNonceAge<TimeSpan.Zero) throw new SecurityException("Negative UTC nonce age refused.");return wholeNonceAge>=TimeSpan.FromSeconds(10);}
        public static Action Require(Action original,Action previous)
        {
            if(original==null) throw new ArgumentNullException("original");
            return delegate {original();if(previous!=null) previous();original();};
        }
    }
}
