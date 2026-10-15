using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Luma.Windows
{
    // These are held observations of untrusted lab inputs, not custody or UTC.
    public sealed class TrustInputLease : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Information
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Information information);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);
        private FileStream stream;
        private Information initial;

        private static Information Inspect(SafeFileHandle handle)
        {
            Information result;
            if (!GetFileInformationByHandle(handle, out result)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((result.Attributes & (0x10U | 0x400U | 0x1000U | 0x40000U | 0x400000U)) != 0 || result.Links != 1)
                throw new InvalidDataException("Trust input is a directory, link, offline file or observed cloud placeholder.");
            return result;
        }

        public static TrustInputLease Acquire(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length > 240 || path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
                path.IndexOf('/') >= 0 || path.IndexOf(':', 2) >= 0 ||
                !String.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Trust input requires a bounded absolute local canonical path.");
            DriveType drive=new DriveInfo(Path.GetPathRoot(path)).DriveType;
            if (drive != DriveType.Fixed && drive != DriveType.Removable)
                throw new InvalidDataException("Trust input requires fixed or removable local storage.");
            SafeFileHandle handle = CreateFile(path, 0x80000000, 1, IntPtr.Zero, 3, 0x08300000, IntPtr.Zero);
            if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try
            {
                Information information=Inspect(handle);
                StringBuilder final=new StringBuilder(512);
                uint length=GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
                if (length == 0 || length >= final.Capacity ||
                    !String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Trust input final file-object identity does not match its exact local path.");
                TrustInputLease lease=new TrustInputLease();
                lease.initial=information;
                lease.stream=new FileStream(handle, FileAccess.Read, 4096, false);
                handle=null;
                return lease;
            }
            finally { if (handle != null) handle.Dispose(); }
        }

        public byte[] Capture(int maximum, bool signature)
        {
            if (stream == null) throw new ObjectDisposedException("TrustInputLease");
            if (maximum < 1 || maximum > 65536) throw new InvalidDataException("Invalid trust capture bound.");
            Check();
            long length=stream.Length;
            if (length < 1 || length > maximum || (signature && length != 64))
                throw new InvalidDataException("Trust input size is outside its fixed bound.");
            byte[] result=new byte[(int)length];
            stream.Position=0;
            int read=0;
            while (read < result.Length)
            {
                int count=stream.Read(result, read, result.Length-read);
                if (count == 0) throw new InvalidDataException("Trust input ended during capture.");
                read+=count;
            }
            if (stream.ReadByte() != -1) throw new InvalidDataException("Trust input changed length during capture.");
            Check();
            return result;
        }

        public void Check()
        {
            if (stream == null) throw new ObjectDisposedException("TrustInputLease");
            Information current=Inspect(stream.SafeFileHandle);
            if (current.Attributes != initial.Attributes || current.Volume != initial.Volume || current.IndexHigh != initial.IndexHigh ||
                current.IndexLow != initial.IndexLow || current.SizeHigh != initial.SizeHigh || current.SizeLow != initial.SizeLow ||
                current.Write.dwHighDateTime != initial.Write.dwHighDateTime || current.Write.dwLowDateTime != initial.Write.dwLowDateTime)
                throw new InvalidDataException("Pinned trust input metadata changed during inspection.");
        }

        public void Dispose()
        {
            if (stream != null) { stream.Dispose(); stream=null; }
        }
    }
}
