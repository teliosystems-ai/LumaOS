using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Observations and arithmetic are data, not caller, ACL or TPM authority.
    public static class HostedStateCapacity
    {
        public const int MaximumFiles = 4096;
        public const long MaximumMetadataBytes = 64L * 1024 * 1024;
        public const long MaximumPackageBytes = 32L * 1024 * 1024 * 1024;
        public const long MaximumAllocatedBytes = MaximumPackageBytes + MaximumMetadataBytes + MaximumFiles * 65536L;
        public const long HostFreeReserveBytes = 1024L * 1024 * 1024;

        public static bool IsPackage(string name)
        {
            return name != null && Regex.IsMatch(name, @"\Aticket-package-[0-9a-f]{32}\.tar\z");
        }

        public static string[] BoundedNames(IEnumerable<string> input)
        {
            if(input == null) throw new ArgumentNullException("input");
            List<string> names = new List<string>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(string name in input) {
                if(names.Count == MaximumFiles) throw new SecurityException("Private authority namespace exceeds its finite file count.");
                if(name == null || name.Length > 80 || !Regex.IsMatch(name, @"\A[a-z0-9][a-z0-9.-]*\z") || name.Contains("..") || !unique.Add(name))
                    throw new SecurityException("Private authority leaf is ambiguous or outside its closed syntax.");
                names.Add(name);
            }
            names.Sort(StringComparer.Ordinal);
            return names.ToArray();
        }

        public static void Require(int files, long metadata, long packages, long allocated, long appendBytes, bool package)
        {
            if(files < 0 || files > MaximumFiles || metadata < 0 || metadata > MaximumMetadataBytes ||
                packages < 0 || packages > MaximumPackageBytes || allocated < 0 || allocated > MaximumAllocatedBytes || appendBytes < 0 ||
                appendBytes > (package ? PackageInspector.MaximumArchiveBytes : Wire.MaximumFrame))
                throw new SecurityException("Private authority physical/logical inventory exceeds its finite budget.");
            if(appendBytes == 0) return;
            if(files == MaximumFiles ||
                appendBytes > (package ? MaximumPackageBytes - packages : MaximumMetadataBytes - metadata) ||
                appendBytes > MaximumAllocatedBytes - allocated || MaximumAllocatedBytes - allocated - appendBytes < 65536)
                throw new IOException("Private authority has no capacity for this new immutable file and allocation slack; retain existing evidence.");
        }

        public static void RequireProjected(int files,long metadata,long packages,long allocated,
            int newFiles,long newMetadata,long newPackages,long newAllocated,HostedPhysicalTail tail)
        {
            Require(files,metadata,packages,allocated,0,false);
            if(tail==null || newFiles<0 || newFiles>MaximumFiles || newMetadata<0 || newMetadata>MaximumMetadataBytes ||
                newPackages<0 || newPackages>MaximumPackageBytes || newAllocated<0 || newAllocated>MaximumAllocatedBytes)
                throw new SecurityException("Invalid finite private-state projection.");
            if((long)files+newFiles+tail.Files>MaximumFiles || metadata+newMetadata+tail.MetadataBytes>MaximumMetadataBytes ||
                packages+newPackages>MaximumPackageBytes || allocated+newAllocated+tail.AllocatedBytes>MaximumAllocatedBytes)
                throw new IOException("Private state must retain the authenticated terminal revocation/abort tail before any new staging.");
        }
    }

    // DATA arithmetic only. Production derives counts from its independently
    // verified journal; constructing this object grants no write or recovery.
    public sealed class HostedPhysicalTail
    {
        public const long DispatchBytes=2048;
        public readonly int Files;
        public readonly long MetadataBytes,AllocatedBytes;
        private HostedPhysicalTail(int files,long metadata) {Files=files;MetadataBytes=metadata;AllocatedBytes=metadata+files*65536L;}
        public static HostedPhysicalTail ForEnrollments(int active,int credits)
        {
            if(active<0 || active>64 || credits<0 || credits>active) throw new SecurityException("Invalid authenticated enrollment-tail counts.");
            // Each healthy revoke retains its dispatch ticket and record. An
            // abort credit additionally funds BOTH the abandoned pair and its
            // replacement pair, not merely the replacement journal event.
            int pairs=active+2*credits;
            return new HostedPhysicalTail(2*pairs,pairs*(HostedJournalCapacity.ReservedEventBytes+DispatchBytes));
        }
    }

    public static class HostedDispatchInventory
    {
        public const int MaximumCurrentAttempts=2;
        public static void RequireNext(int currentAttempts,bool replacement)
        {
            if(currentAttempts<0 || currentAttempts>MaximumCurrentAttempts ||
                (!replacement && currentAttempts!=0) || (replacement && currentAttempts!=1))
                throw new SecurityException("The finite current-head dispatch/abort attempt budget is exhausted; retain evidence and fence authority for separately reviewed forensics.");
        }
        public static int Validate(AuthorityIdentity identity,JournalHistory history,IEnumerable<string> leaves,Func<string,byte[]> read)
        {
            if(identity==null || history==null || read==null) throw new ArgumentNullException("dispatch inventory");
            HashSet<string> names=new HashSet<string>(HostedStateCapacity.BoundedNames(leaves),StringComparer.Ordinal);
            JournalEntry pending=names.Contains("pending.bin")?JournalEntry.Decode(identity,read("pending.bin")):null;
            JournalEntry abort=names.Contains("abort.intent")?JournalEntry.Decode(identity,read("abort.intent")):null;
            foreach(JournalEntry entry in new[]{pending,abort}) if(entry!=null &&
                !(entry.Sequence==history.Sequence+1 && entry.PreviousHead==history.Head && entry.PreviousRecord==history.Record) &&
                !(pending==entry && history.Last!=null && Wire.Equal(history.Last.Bytes,entry.Bytes)))
                throw new SecurityException("Retained preparation does not match its exact current or already-published authority head.");
            foreach(JournalEntry entry in new[]{pending,abort}) if(entry!=null && entry.Kind==JournalKind.NvWriteAborted) {
                NvAbortEvent replacement=NvAbortEvent.Decode(identity,entry.Payload);replacement.Matches(entry);
                string abandoned="ticket-d-"+replacement.Abandoned.RecordSha256+".bin";
                if(!names.Contains(abandoned) || !Wire.Equal(read(abandoned),replacement.Abandoned.Encode()))
                    throw new SecurityException("Replacement preparation lost its exact independently signed abandoned dispatch evidence.");
            }
            HashSet<string> current=new HashSet<string>(StringComparer.Ordinal);
            foreach(string leaf in names) {
                if(!leaf.StartsWith("ticket-d-",StringComparison.Ordinal)) continue;
                if(!Regex.IsMatch(leaf,@"\Aticket-d-[0-9a-f]{64}\.bin\z")) throw new SecurityException("Dispatch ticket has a malformed private leaf.");
                DispatchTicket ticket=DispatchTicket.Decode(identity,read(leaf));
                if(leaf!="ticket-d-"+ticket.RecordSha256+".bin" || ticket.Sequence>history.Sequence+1)
                    throw new SecurityException("Signed dispatch ticket crosses its fixed record/sequence.");
                if(ticket.Sequence<=history.Sequence) continue;
                if(ticket.PreviousHead!=history.Head || !current.Add(ticket.RecordSha256) || current.Count>MaximumCurrentAttempts)
                    throw new SecurityException("Current-head signed dispatch attempts exceed the finite retained recovery budget.");
                JournalEntry matched=pending!=null && pending.RecordSha256==ticket.RecordSha256?pending:
                    abort!=null && abort.RecordSha256==ticket.RecordSha256?abort:null;
                if(matched==null) foreach(string prefix in new[]{"ticket-a-","ticket-u-"}) {
                    string retained=prefix+ticket.RecordSha256+".bin";
                    if(names.Contains(retained)) {matched=JournalEntry.Decode(identity,read(retained));break;}
                }
                if(matched==null || matched.Sequence!=history.Sequence+1 || matched.PreviousRecord!=history.Record)
                    throw new SecurityException("Signed uncommitted dispatch ticket lacks its exact retained preparation; no authority fallback, automatic retry or purge.");
                ticket.Matches(matched);
            }
            if((pending!=null && pending.Sequence==history.Sequence+1 && !current.Contains(pending.RecordSha256)) ||
                (abort!=null && !current.Contains(abort.RecordSha256)) || (current.Count>0 && pending==null && abort==null))
                throw new SecurityException("Current signed dispatch/preparation namespace is incomplete; original authority remains fenced for reviewed forensics.");
            return current.Count;
        }
    }

    public sealed class HostedFileAllocation
    {
        [StructLayout(LayoutKind.Sequential)] private struct Standard {
            public long Allocation, End;
            public uint Links;
            public byte DeletePending, Directory;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Allocation { public long Bytes; }
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, IntPtr buffer, uint bytes);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref Allocation value, uint bytes);
        public readonly long LogicalBytes, AllocatedBytes;
        private HostedFileAllocation(long logical, long allocated) {LogicalBytes = logical; AllocatedBytes = allocated;}

        public static HostedFileAllocation Observe(SafeFileHandle handle)
        {
            if(handle == null || handle.IsInvalid || handle.IsClosed) throw new SecurityException("A held regular-file handle is required.");
            int size = Marshal.SizeOf(typeof(Standard));
            IntPtr memory = Marshal.AllocHGlobal(65536);
            try {
                if(!GetFileInformationByHandleEx(handle, 1, memory, (uint)size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                Standard value = (Standard)Marshal.PtrToStructure(memory, typeof(Standard));
                if(value.End < 0 || value.Allocation < 0 || value.Links != 1 || value.DeletePending != 0 || value.Directory != 0)
                    throw new SecurityException("Allocation observation is not an existing single-link regular file.");
                // FILE_STREAM_INFO: exactly the unnamed data stream. Additional
                // named streams cannot hide physical bytes from this budget.
                if(!GetFileInformationByHandleEx(handle, 7, memory, 65536)) throw new Win32Exception(Marshal.GetLastWin32Error());
                int next = Marshal.ReadInt32(memory, 0), count = Marshal.ReadInt32(memory, 4);
                long logical = Marshal.ReadInt64(memory, 8), allocated = Marshal.ReadInt64(memory, 16);
                if(next != 0 || count != 14 || Marshal.PtrToStringUni(IntPtr.Add(memory, 24), 7) != "::$DATA" ||
                    logical != value.End || allocated != value.Allocation)
                    throw new SecurityException("Private authority has named streams or inconsistent allocation observations.");
                return new HostedFileAllocation(value.End, value.Allocation);
            } finally {Marshal.FreeHGlobal(memory);}
        }

        public static HostedFileAllocation ReserveEmpty(SafeFileHandle handle, long bytes)
        {
            if(bytes < 1 || bytes > PackageInspector.MaximumArchiveBytes) throw new SecurityException("Physical reservation exceeds the closed file bound.");
            HostedFileAllocation before = Observe(handle);
            if(before.LogicalBytes != 0 || before.AllocatedBytes != 0) throw new SecurityException("Only a new empty, unallocated file may be reserved.");
            Allocation value = new Allocation {Bytes = bytes};
            if(!SetFileInformationByHandle(handle, 5, ref value, (uint)Marshal.SizeOf(typeof(Allocation))))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Private file allocation failed before dispatch; preserve the partial file.");
            HostedFileAllocation after = Observe(handle);
            if(after.LogicalBytes != 0 || after.AllocatedBytes < bytes || after.AllocatedBytes - bytes > 65536)
                throw new SecurityException("Actual physical allocation readback differs; no data or TPM dispatch is permitted.");
            return after;
        }
    }
}
