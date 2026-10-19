[CmdletBinding()]
param([Parameter(Mandatory)][string] $BuildRoot,[Parameter(Mandatory)][string] $FixtureRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$build=& (Join-Path $PSScriptRoot 'build-hosted-authority.ps1') -BuildRoot $BuildRoot -LibraryOnly
foreach ($name in @('Luma.PlatformSignature.dll','Luma.PlatformCustody.dll','Luma.PackageInspector.dll','Luma.HostedAuthority.Library.dll')) {
    $null=[Reflection.Assembly]::LoadFrom((Join-Path $build.work_directory $name))
}
$parent=Get-Item -LiteralPath $FixtureRoot -Force
if ($parent -isnot [IO.DirectoryInfo] -or $parent.FullName -notmatch '\A[A-Za-z]:\\' -or
    [IO.DriveInfo]::new([IO.Path]::GetPathRoot($parent.FullName)).DriveFormat -cne 'NTFS') {throw 'Actual fixture requires an existing local NTFS directory.'}
for ($check=$parent;$null -ne $check;$check=$check.Parent) {
    if (($check.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Fixture path may not traverse reparse points.'}
}
$work=Join-Path $parent.FullName ('hosted-capacity-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($work)
$script:Assertions=0
function Assert-Capacity([bool] $Condition,[string] $Message) {if (-not $Condition) {throw $Message};$script:Assertions++}
function Assert-CapacityThrows([scriptblock] $Action,[string] $Message) {
    $refused=$false
    try {$null=& $Action} catch {
        $leaf=$_.Exception.GetBaseException()
        if ($leaf -isnot [Security.SecurityException] -and $leaf -isnot [IO.IOException] -and $leaf -isnot [IO.InvalidDataException] -and $leaf -isnot [ArgumentException]) {throw}
        $refused=$true
    }
    Assert-Capacity $refused $Message
}
[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,0,0,1,$false)
Assert-Capacity $true 'Empty metadata admission refused.'
[Luma.Windows.Hosted.HostedStateCapacity]::Require(4096,67108864,34359738368,34695282688,0,$false)
Assert-Capacity $true 'Exact closed full read-only inventory refused.'
foreach ($count in @(-1,4097)) {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require($count,0,0,0,0,$false)} 'Invalid file count accepted.'}
foreach ($value in @(-1L,67108865L,[long]::MaxValue)) {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,$value,0,0,0,$false)} 'Invalid metadata sum accepted.'}
foreach ($value in @(-1L,34359738369L,[long]::MaxValue)) {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,$value,0,0,$false)} 'Invalid package sum accepted.'}
foreach ($value in @(-1L,34695282689L,[long]::MaxValue)) {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,0,$value,0,$false)} 'Invalid allocation sum accepted.'}
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(4096,0,0,0,1,$false)} 'New file exceeded the full namespace.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,67108864,0,0,1,$false)} 'New metadata exceeded logical budget.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,34359738368,0,1,$true)} 'New package exceeded logical budget.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,0,34695217152,1,$false)} 'Physical allocation omitted per-file slack.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,0,0,65537,$false)} 'Metadata exceeded one wire frame.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::Require(0,0,0,0,17179869185,$true)} 'Package exceeded exact archive ceiling.'
foreach ($name in @(('ticket-package-'+('a'*32)+'.tar'),('ticket-package-'+('0'*32)+'.tar'))) {
    Assert-Capacity ([Luma.Windows.Hosted.HostedStateCapacity]::IsPackage($name)) 'Canonical package leaf not classified.'
}
foreach ($name in @('ticket-package-a.tar',('ticket-package-'+('A'*32)+'.tar'),('ticket-package-'+('a'*32)+'.tar.extra'),'metadata.bin')) {
    Assert-Capacity (-not [Luma.Windows.Hosted.HostedStateCapacity]::IsPackage($name)) 'Noncanonical leaf adopted as package.'
}
[string[]]$names=[Luma.Windows.Hosted.HostedStateCapacity]::BoundedNames([string[]]@('z.bin','a.bin'))
Assert-Capacity (($names -join '|') -ceq 'a.bin|z.bin') 'Namespace order differs from ordinal canonical order.'
foreach ($invalid in @('..','a..b','Uppercase','a/leaf','a:stream','a\leaf','a ','',('a'*81))) {
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::BoundedNames([string[]]@($invalid))} 'Invalid leaf syntax accepted.'
}
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::BoundedNames([string[]]@('a.bin','a.bin'))} 'Duplicate immutable file accepted.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::BoundedNames([string[]](1..4097 | ForEach-Object {$_.ToString('x')}))} 'Oversized namespace enumerated as admissible.'
$path=Join-Path $work 'preallocated.bin'
$stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $before=[Luma.Windows.Hosted.HostedFileAllocation]::Observe($stream.SafeFileHandle)
    Assert-Capacity ($before.LogicalBytes -eq 0 -and $before.AllocatedBytes -eq 0) 'New NTFS file did not start empty.'
    $reserved=[Luma.Windows.Hosted.HostedFileAllocation]::ReserveEmpty($stream.SafeFileHandle,8193)
    Assert-Capacity ($reserved.LogicalBytes -eq 0 -and $reserved.AllocatedBytes -ge 8193 -and $reserved.AllocatedBytes -le 73729) 'Actual allocation was not reserved separately from EOF.'
    Assert-Capacity ($stream.Length -eq 0) 'Reservation exposed uninitialized readable bytes.'
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::ReserveEmpty($stream.SafeFileHandle,8193)} 'A nonempty reservation was repeated.'
    $bytes=[byte[]]::new(8193);$bytes[8192]=17
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
    $after=[Luma.Windows.Hosted.HostedFileAllocation]::Observe($stream.SafeFileHandle)
    Assert-Capacity ($after.LogicalBytes -eq 8193 -and $after.AllocatedBytes -ge 8193) 'Actual committed EOF/allocation differs.'
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::ReserveEmpty($stream.SafeFileHandle,1)} 'Existing written file admitted for new allocation.'
} finally {$stream.Dispose()}
foreach ($value in @(0L,-1L,17179869185L)) {
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::ReserveEmpty($null,$value)} 'Invalid allocation request accepted.'
}
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::Observe($null)} 'Missing handle accepted.'
$alternate=Join-Path $work 'named-stream.bin'
[IO.File]::WriteAllBytes($alternate,[byte[]]@(1))
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LumaCapacityStreamFixture {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    public static void CreateNamed(string path) {
        SafeFileHandle handle=CreateFile(path+":hidden",0x40000000,3,IntPtr.Zero,1,0x00200000,IntPtr.Zero);
        if(handle.IsInvalid) {int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
        using(FileStream stream=new FileStream(handle,FileAccess.Write)) {stream.WriteByte(2);stream.Flush(true);}
    }
}
'@
[LumaCapacityStreamFixture]::CreateNamed($alternate)
$stream=[IO.FileStream]::new($alternate,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::Observe($stream.SafeFileHandle)} 'Hidden named stream omitted from private allocation budget.'} finally {$stream.Dispose()}
$hard=Join-Path $work 'hard-linked.bin'
$null=New-Item -ItemType HardLink -Path $hard -Target $path
$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {Assert-CapacityThrows {[Luma.Windows.Hosted.HostedFileAllocation]::Observe($stream.SafeFileHandle)} 'Multiple hard links accepted in private state.'} finally {$stream.Dispose()}
$zeroTail=[Luma.Windows.Hosted.HostedPhysicalTail]::ForEnrollments(0,0)
$tail=[Luma.Windows.Hosted.HostedPhysicalTail]::ForEnrollments(2,1)
Assert-Capacity ($tail.Files -eq 8 -and $tail.MetadataBytes -eq 40960 -and $tail.AllocatedBytes -eq 565248) 'Physical tail must fund every healthy revoke and both pairs of each finite abort credit.'
foreach ($counts in @(@(-1,0),@(65,0),@(1,-1),@(1,2))) {
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedPhysicalTail]::ForEnrollments($counts[0],$counts[1])} 'Invalid derived physical-tail counts accepted.'
}
[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4088,0,0,0,0,0,0,0,$tail)
Assert-Capacity $true 'Exact terminal physical namespace floor was refused.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4088,0,0,0,1,1,0,65537,$tail)} 'An unrelated metadata ticket consumed a reserved terminal slot.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4088,0,0,0,1,0,1024,66560,$tail)} 'A package consumed a reserved terminal slot.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4095,0,0,0,2,10240,0,141312,$zeroTail)} 'A two-file stage was admitted with only its dispatch-ticket slot available.'
$afterRevoke=[Luma.Windows.Hosted.HostedPhysicalTail]::ForEnrollments(1,1)
[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4088,67108864-$tail.MetadataBytes,0,34695282688-$tail.AllocatedBytes,2,10240,0,141312,$afterRevoke)
Assert-Capacity $true 'Healthy terminal revoke could not consume only its own reserved pair.'
$afterAbort=[Luma.Windows.Hosted.HostedPhysicalTail]::ForEnrollments(2,0)
[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(4090,67108864-$tail.MetadataBytes+10240,0,34695282688-$tail.AllocatedBytes+141312,2,10240,0,141312,$afterAbort)
Assert-Capacity $true 'The old retained pair plus replacement pair exceeded its funded abort credit.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(0,67108864-$tail.MetadataBytes,0,0,1,1,0,65537,$tail)} 'Metadata admission consumed reserved revocation/abort bytes.'
Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(0,0,0,34695282688-$tail.AllocatedBytes,1,1,0,65537,$tail)} 'Allocation admission consumed reserved revocation/abort blocks.'
foreach ($value in @(-1L,[long]::MaxValue)) {
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedStateCapacity]::RequireProjected(0,0,0,0,0,$value,0,0,$zeroTail)} 'Projection accepted a negative or overflowing future byte count.'
}
[Luma.Windows.Hosted.HostedDispatchInventory]::RequireNext(0,$false)
[Luma.Windows.Hosted.HostedDispatchInventory]::RequireNext(1,$true)
Assert-Capacity $true 'Closed first-dispatch and one replacement attempt admission refused.'
foreach ($case in @(@(1,$false),@(2,$false),@(0,$true),@(2,$true),@(-1,$false),@(3,$true))) {
    Assert-CapacityThrows {[Luma.Windows.Hosted.HostedDispatchInventory]::RequireNext($case[0],$case[1])} 'Repeated pre-dispatch/abort attempts could consume the protected physical tail.'
}
Add-Type -ReferencedAssemblies @((Join-Path $build.work_directory 'Luma.HostedAuthority.Library.dll'),
    (Join-Path $build.work_directory 'Luma.PlatformSignature.dll'),(Join-Path $build.work_directory 'Luma.PlatformCustody.dll'),
    (Join-Path $build.work_directory 'Luma.PackageInspector.dll'),'System.dll','System.Core.dll','System.Security.dll') -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Luma.Windows.Hosted;
public static class LumaCapacityLifecycleFixture {
    private static JournalEntry Sign(AuthorityIdentity id,ECDsaCng key,ulong sequence,JournalKind kind,string head,string previous,string payload) {
        JournalEntry entry=JournalEntry.Prepare(id,sequence,kind,head,previous,id.FirstAdminSid,Encoding.ASCII.GetBytes(payload));
        return entry.Signed(id,key.SignData(entry.SigningInput));
    }
    private static DispatchTicket Ticket(AuthorityIdentity id,ECDsaCng key,JournalEntry entry,ulong boot,uint reset) {
        byte[] input=DispatchTicket.SigningInput(id,entry,boot,new TpmEpoch(1,1,reset,1,true));
        return DispatchTicket.Signed(id,input,key.SignData(input));
    }
    public static int Validate(int mode) {
        using(CngKey release=CngKey.Create(CngAlgorithm.ECDsaP256))
        using(CngKey time=CngKey.Create(CngAlgorithm.ECDsaP256))
        using(CngKey signing=CngKey.Create(CngAlgorithm.ECDsaP256))
        using(ECDsaCng key=new ECDsaCng(signing)) {
            key.HashAlgorithm=CngAlgorithm.Sha256;
            AuthorityIdentity id=new AuthorityIdentity("host-deployment",new string('a',64),"S-1-5-21-100-200-300-1001","lab",
                release.Export(CngKeyBlobFormat.EccPublicBlob),time.Export(CngKeyBlobFormat.EccPublicBlob),signing.Export(CngKeyBlobFormat.EccPublicBlob),new string('b',64),new string('c',64));
            JournalEntry genesis=Sign(id,key,1,JournalKind.Commission,new string('0',64),new string('0',64),"isolated journal codec fixture; not commissioned hardware");
            JournalHistory history=JournalHistory.Replay(id,new byte[][]{genesis.Bytes});
            JournalEntry entry=Sign(id,key,2,JournalKind.ImportPrepared,history.Head,history.Record,"bounded software capacity fixture; no import execution");
            DispatchTicket ticket=Ticket(id,key,entry,1,1);string leaf="ticket-d-"+entry.RecordSha256+".bin";
            Dictionary<string,byte[]> files=new Dictionary<string,byte[]>(StringComparer.Ordinal);
            if(mode==0 || mode==3) {
                if(mode==3) {files.Add("ticket-r-"+new string('d',64)+".bin",new byte[]{1});files.Add("ticket-s-"+new string('d',64)+".bin",new byte[]{2});}
            } else {
                files.Add(leaf,ticket.Encode());
                if(mode!=2 && mode!=12) files.Add("pending.bin",entry.Bytes);
                if(mode==4) files[leaf][files[leaf].Length-1]^=1;
                if(mode==5) {files.Remove(leaf);files.Add("ticket-d-"+new string('0',64)+".bin",ticket.Encode());}
                if(mode==6) files.Remove(leaf);
                if(mode==7) history=JournalHistory.Replay(id,new byte[][]{genesis.Bytes,entry.Bytes});
                if(mode>=8 && mode<=11 || mode==17) {
                    NvAbortEvent aborted=new NvAbortEvent(ticket,2,new TpmEpoch(2,2,2,1,true),new byte[32] {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
                    JournalEntry replacement=JournalEntry.Prepare(id,2,JournalKind.NvWriteAborted,history.Head,history.Record,id.FirstAdminSid,aborted.Encode());
                    replacement=replacement.Signed(id,key.SignData(replacement.SigningInput));
                    DispatchTicket next=Ticket(id,key,replacement,2,2);files.Add("ticket-d-"+replacement.RecordSha256+".bin",next.Encode());
                    if(mode==8) files.Add("abort.intent",replacement.Bytes);
                    else {files["pending.bin"]=replacement.Bytes;files.Add("ticket-a-"+entry.RecordSha256+".bin",entry.Bytes);}
                    if(mode==10) history=JournalHistory.Replay(id,new byte[][]{genesis.Bytes,replacement.Bytes});
                    if(mode==11) {
                        JournalEntry extra=Sign(id,key,2,JournalKind.ImportPrepared,history.Head,history.Record,"third unsupported same-head attempt");
                        files.Add("ticket-d-"+extra.RecordSha256+".bin",Ticket(id,key,extra,3,3).Encode());files.Add("ticket-u-"+extra.RecordSha256+".bin",extra.Bytes);
                    }
                    if(mode==17) files.Remove(leaf);
                }
                if(mode==12) files.Add("ticket-u-"+entry.RecordSha256+".bin",entry.Bytes);
                if(mode==13) {
                    JournalEntry future=Sign(id,key,3,JournalKind.ImportPrepared,history.Head,history.Record,"future sequence");
                    files.Clear();files.Add("ticket-d-"+future.RecordSha256+".bin",Ticket(id,key,future,1,1).Encode());
                }
                if(mode==14) {
                    JournalEntry fork=Sign(id,key,2,JournalKind.ImportPrepared,new string('e',64),history.Record,"wrong parent");
                    files.Clear();files.Add("pending.bin",fork.Bytes);files.Add("ticket-d-"+fork.RecordSha256+".bin",Ticket(id,key,fork,1,1).Encode());
                }
                if(mode==15) files["pending.bin"]=new byte[0];
                if(mode==16) {files.Remove(leaf);files.Add("ticket-d-malformed.bin",ticket.Encode());}
            }
            if(mode==0 && HostedJournalCapacity.ProjectedPhysicalTail(id,history,entry).Files!=0) throw new Exception("Unrelated candidate invented enrollment authority.");
            return HostedDispatchInventory.Validate(id,history,files.Keys,delegate(string name){return files[name];});
        }
    }
}
'@
foreach ($case in @(@(0,0),@(1,1),@(3,0),@(7,0),@(8,2),@(9,2),@(10,0))) {
    Assert-Capacity ([LumaCapacityLifecycleFixture]::Validate($case[0]) -eq $case[1]) ('Actual signed dispatch/preparation/finalization lifecycle refused mode '+$case[0])
}
foreach ($mode in @(2,4,5,6,11,12,13,14,15,16,17)) {
    Assert-CapacityThrows {[LumaCapacityLifecycleFixture]::Validate($mode)} ('Signed orphan, modified, missing, excess or forked dispatch evidence accepted mode '+$mode)
}
[pscustomobject][ordered]@{schema_version=1;status='hosted-physical-capacity-software-tests-passed';assertions=$script:Assertions;
    build_directory=$build.work_directory;fixture_directory=$work;actual_ntfs_allocation_and_eof_observed=$true;
    named_stream_and_hardlink_refusal_observed=$true;actual_ephemeral_bcrypt_dispatch_lifecycle_tests=$true;
    physical_revocation_and_abort_tail_arithmetic_tested=$true;private_system_authority_store_opened=$false;
    hardware_custody_invoked=$false;host_tpm_mutated=$false;service_installed=$false;distribution_imported=$false;
    installed_acl_and_powerloss_durability_qualified=$false;production_qualified=$false;gate_closing=$false} | ConvertTo-Json -Depth 6
