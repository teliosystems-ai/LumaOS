using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows.Hosted
{
    // Stable local objects only, not account/grant/custody authority. Unlike a
    // public source snapshot, an installed parent may legitimately gain a new
    // child generation. Its identity and owner/DACL must remain unchanged.
    internal sealed class InstalledInputLease : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] private struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint sharing,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,out Information information);
        [DllImport("kernel32.dll",SetLastError=true)] private static extern uint GetFileType(SafeFileHandle file);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,uint maximum,uint flags);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern uint GetSecurityInfo(SafeFileHandle file,int kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
        private sealed class Node {internal SafeFileHandle Handle;internal Information Initial;internal bool Directory;internal byte[] Security;}
        private readonly List<Node> nodes=new List<Node>();private FileStream stream;
        private static Information Inspect(SafeFileHandle handle,bool directory) {
            Information value;if(GetFileType(handle)!=1 || !GetFileInformationByHandle(handle,out value)) throw new IOException("Installed inputs must be actual local disk objects.");
            if(((value.Attributes&0x10)!=0)!=directory || (value.Attributes&(0x400|0x1000|0x40000|0x400000))!=0 || !directory && value.Links!=1) throw new SecurityException("Installed input is linked, recalled, cloud-backed or the wrong type.");return value;
        }
        private static byte[] Security(SafeFileHandle handle) {
            IntPtr owner,group,dacl,sacl,descriptor;uint result=GetSecurityInfo(handle,1,7,out owner,out group,out dacl,out sacl,out descriptor);if(result!=0) throw new Win32Exception((int)result);
            try {uint count=GetSecurityDescriptorLength(descriptor);if(count<20 || count>65536) throw new SecurityException("Installed object ACL exceeds bound.");byte[] bytes=new byte[count];Marshal.Copy(descriptor,bytes,0,(int)count);return bytes;}finally {LocalFree(descriptor);}
        }
        private static bool Same(Information before,Information after,bool directory) {
            return before.Attributes==after.Attributes && before.Volume==after.Volume && before.IndexHigh==after.IndexHigh && before.IndexLow==after.IndexLow && before.Creation.dwHighDateTime==after.Creation.dwHighDateTime && before.Creation.dwLowDateTime==after.Creation.dwLowDateTime &&
                (directory || before.Links==after.Links && before.SizeHigh==after.SizeHigh && before.SizeLow==after.SizeLow && before.Write.dwHighDateTime==after.Write.dwHighDateTime && before.Write.dwLowDateTime==after.Write.dwLowDateTime);
        }
        private SafeFileHandle Open(string path,bool directory) {
            SafeFileHandle handle=CreateFile(path,directory?0x20080U:0x80020080U,directory?3U:1U,IntPtr.Zero,3,directory?0x02300000U:0x08300000U,IntPtr.Zero);
            try {if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());Information info=Inspect(handle,directory);StringBuilder final=new StringBuilder(512);uint count=GetFinalPathNameByHandle(handle,final,512,0);
                if(count==0 || count>=512 || !String.Equals(final.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase)) throw new SecurityException("Installed input final path differs from the selected exact object.");
                nodes.Add(new Node {Handle=handle,Initial=info,Directory=directory,Security=Security(handle)});return handle;
            }catch {handle.Dispose();throw;}
        }
        internal static InstalledInputLease Acquire(string path) {
            PlatformInputLease.ValidatePath(path);InstalledInputLease lease=new InstalledInputLease();
            try {string current=path.Substring(0,3);lease.Open(current,true);string[] parts=path.Substring(3).Split('\\');if(parts.Length>32) throw new SecurityException("Installed input exceeds ancestor handle bound.");
                for(int index=0;index<parts.Length-1;index++) {current=Path.Combine(current,parts[index]);lease.Open(current,true);}SafeFileHandle file=lease.Open(path,false);
                lease.stream=new FileStream(file,FileAccess.Read,32768,false);lease.Check();return lease;
            }catch {lease.Dispose();throw;}
        }
        internal long Length {get{Check();return stream.Length;}}internal Stream Rewind() {Check();stream.Position=0;return stream;}
        internal void Check() {
            if(stream==null) throw new ObjectDisposedException("InstalledInputLease");foreach(Node node in nodes) if(!Same(node.Initial,Inspect(node.Handle,node.Directory),node.Directory) || !Wire.Equal(node.Security,Security(node.Handle))) throw new SecurityException("Held installed object identity, exact file metadata or owner/DACL changed.");
        }
        public void Dispose() {if(stream!=null) {stream.Dispose();stream=null;}foreach(Node node in nodes) node.Handle.Dispose();nodes.Clear();}
    }
}
