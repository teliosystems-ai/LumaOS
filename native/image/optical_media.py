"""Distinct EFI El Torito installer media, not a GPT image renamed as ISO.

Only private isolated Linux build files are used. The optical UKI authenticates
the same verity root and never contains installed Admin PCR approval. The
independent extent checker compares actual ISO file bytes to external pins; ISO
labels and generated receipts do not establish signature/custody authority.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import struct
import subprocess
import tempfile
import time

SECTOR = 2048
MIB = 1024**2
MAX_ISO = 32*1024**3
VOLUME = b'LUMA_OPTICAL'


def require(value, message):
    if not value:
        raise ValueError(message)


def run(*args, timeout=1800, pass_fds=(), output_fd=None):
    child=subprocess.Popen([str(arg) for arg in args],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if output_fd is None else output_fd,stderr=subprocess.PIPE,pass_fds=pass_fds,
        env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'})
    selector=selectors.DefaultSelector();output=bytearray();errors=bytearray();deadline=time.monotonic()+timeout
    try:
        if child.stdout is not None:selector.register(child.stdout,selectors.EVENT_READ,output)
        selector.register(child.stderr,selectors.EVENT_READ,errors)
        while selector.get_map():
            require(time.monotonic()<deadline,'optical tool observation deadline exceeded')
            for key,_ in selector.select(min(0.25,max(0,deadline-time.monotonic()))):
                data=os.read(key.fd,65536)
                if not data:selector.unregister(key.fileobj)
                else:
                    key.data.extend(data)
                    require(len(output)+len(errors)<=MIB,'optical tool diagnostics exceed bound')
        code=child.wait(timeout=max(0.001,deadline-time.monotonic()))
        if code:
            error=subprocess.CalledProcessError(code,args,bytes(output),bytes(errors))
            error.add_note(bytes(errors[:4096]).decode('utf8','replace'))
            raise error
        return bytes(output)
    finally:
        selector.close()
        if child.poll() is None:child.kill()
        child.wait()
        if child.stdout is not None:child.stdout.close()
        child.stderr.close()


def identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def seal(path):
    path = Path(path)
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=MAX_ISO,
                'optical member must be bounded single-link regular data')
        value = range_hash(fd,[(0,before.st_size)])
        require(identity(before)==identity(os.fstat(fd))==identity(path.lstat()), 'optical member changed during hashing')
        return {'bytes':before.st_size,'sha256':value},identity(before)
    finally:
        os.close(fd)


def range_hash(fd, extents):
    value = hashlib.sha256()
    for offset,size in extents:
        while size:
            data = os.pread(fd,min(MIB,size),offset)
            require(data,'truncated optical extent')
            value.update(data);offset+=len(data);size-=len(data)
    return value.hexdigest()


def both32(data, offset):
    little,big=struct.unpack_from('<I',data,offset)[0],struct.unpack_from('>I',data,offset+4)[0]
    require(little==big,'ambiguous ISO endian integer')
    return little


def both16(data, offset):
    little,big=struct.unpack_from('<H',data,offset)[0],struct.unpack_from('>H',data,offset+2)[0]
    require(little==big,'ambiguous ISO endian integer')
    return little


def verify_iso(path, expected):
    """Independently parse flat ISO9660 and EFI catalog; hash every extent."""
    require(type(expected) is dict and 'efi.img' in expected and len(expected)<=16,'bounded expected EFI ISO inventory required')
    for name,value in expected.items():
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,30}',name) and type(value) is dict
                and set(value)=={'bytes','sha256'} and type(value['bytes']) is int and 0<value['bytes']<=MAX_ISO
                and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'closed independent optical member pins required')
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);length=before.st_size
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 20*SECTOR<=length<=MAX_ISO
                and length%SECTOR==0,'bounded regular sector-aligned ISO required')
        require(not any(os.pread(fd,16*SECTOR,0)),'hybrid MBR/GPT/system-area boot paths refused')
        pvd=boot=None;terminated=False
        for sector in range(16,48):
            data=os.pread(fd,SECTOR,sector*SECTOR)
            require(len(data)==SECTOR and data[1:6]==b'CD001' and data[6]==1,'invalid ISO volume descriptor')
            if data[0]==255:
                terminated=True;break
            if data[0]==1:
                require(pvd is None,'duplicate ISO primary volume');pvd=data
            elif data[0]==0:
                require(boot is None and data[7:39].rstrip(b'\0 ')==b'EL TORITO SPECIFICATION','unsupported optical boot record');boot=data
            else:
                raise ValueError('alternate optical namespace descriptor refused')
        require(terminated and pvd is not None and boot is not None,'missing ISO primary, boot or terminator descriptor')
        require(pvd[40:72].rstrip(b' ')==VOLUME and both32(pvd,80)*SECTOR==length,
                'optical volume identity or exact image length differs')
        require(struct.unpack_from('<H',pvd,128)[0]==SECTOR and struct.unpack_from('>H',pvd,130)[0]==SECTOR,
                'optical sector geometry differs')
        require(both16(pvd,120)==1 and both16(pvd,124)==1,'multivolume ISO refused')
        root=pvd[156:190];start,size=both32(root,2)*SECTOR,both32(root,10)
        data_floor=(sector+1)*SECTOR
        require(root[0]==34 and root[1]==0 and root[25]==2 and root[26:28]==b'\0\0'
                and both16(root,28)==1 and root[32:34]==b'\x01\0'
                and 0<size<=MIB and start>=data_floor and start+size<=length,
                'bounded flat optical root directory required')
        table_size=both32(pvd,132)
        require(table_size==10 and pvd[144:148]==bytes(4) and pvd[152:156]==bytes(4),
                'only the sole flat root path table is supported')
        table_spans=[]
        for where,endian in ((140,'<'),(148,'>')):
            at=struct.unpack_from(endian+'I',pvd,where)[0]*SECTOR
            require(data_floor<=at and at+table_size<=length,'path table outside ISO')
            table=os.pread(fd,table_size,at)
            require(table==b'\x01\0'+struct.pack(endian+'IH',start//SECTOR,1)+b'\0\0',
                    'path table does not identify the sole exact root')
            table_spans.append((at,at+table_size))
        directory=os.pread(fd,size,start);records={};offset=0;pending=None;dots=set()
        while offset<size:
            width=directory[offset]
            if width==0:
                offset=((offset//SECTOR)+1)*SECTOR;continue
            require(34<=width<=255 and offset+width<=size and offset//SECTOR==(offset+width-1)//SECTOR,
                    'invalid optical directory record bound')
            item=directory[offset:offset+width];offset+=width
            count=item[32];require(33+count<=width,'truncated optical filename')
            require(width==33+count+(1 if (33+count)%2 else 0),
                    'alternate Rock Ridge/system-use namespace refused')
            raw=item[33:33+count]
            require(both16(item,28)==1,'cross-volume optical member refused')
            if raw in (b'\0',b'\1'):
                require(raw not in dots and item[25]==2 and item[1]==0 and item[26:28]==b'\0\0'
                        and both32(item,2)*SECTOR==start and both32(item,10)==size,
                        'optical dot member does not identify the sole root')
                dots.add(raw);continue
            name=raw.decode('ascii')
            require(name.endswith(';1'),'unsupported optical file version')
            name=name[:-2]
            require(name in expected or name=='boot.catalog','unreviewed optical root member')
            require(item[25] in (0,128) and item[1]==0 and item[26:28]==b'\0\0',
                    'linked, directory or interleaved optical member refused')
            begin,count=both32(item,2)*SECTOR,both32(item,10)
            require(0<count<=MAX_ISO and begin>=data_floor and begin+count<=length,'optical member extent outside image')
            require(item[25]!=128 or count%SECTOR==0,'nonfinal optical extent must contain complete sectors')
            require(pending is None or pending==name,'noncontiguous ISO multi-extent member')
            require(name not in records or pending==name,'duplicate optical member')
            records.setdefault(name,[]).append((begin,count));require(len(records[name])<=32,'too many optical file extents')
            pending=name if item[25]==128 else None
        require(pending is None and dots=={b'\0',b'\1'} and set(records)==set(expected)|{'boot.catalog'},'missing or unfinished optical file inventory')
        spans=[(begin,begin+count) for values in records.values() for begin,count in values]
        spans.append((start,start+size))
        spans.extend(table_spans)
        ordered=sorted(spans)
        require(all(left[1]<=right[0] for left,right in zip(ordered,ordered[1:])),'aliased optical extents')
        for name,value in expected.items():
            require(sum(size for _,size in records[name])==value['bytes'] and range_hash(fd,records[name])==value['sha256'],
                    'actual optical member bytes differ from independent pin: '+name)
        catalog_at=struct.unpack_from('<I',boot,71)[0]*SECTOR
        require(records['boot.catalog']==[(catalog_at,SECTOR)],'El Torito catalog location or length differs')
        catalog=os.pread(fd,SECTOR,catalog_at)
        require(catalog[0]==1 and catalog[1]==0xef and catalog[2:4]==b'\0\0' and catalog[30:32]==b'\x55\xaa'
                and sum(struct.unpack('<16H',catalog[:32]))%65536==0,'invalid EFI El Torito validation entry')
        entry=catalog[32:64]
        efi_bytes=expected['efi.img']['bytes']
        require(MIB<=efi_bytes<=512*MIB and efi_bytes%512==0,'bounded sector-aligned EFI FAT image required')
        sectors=(efi_bytes+511)//512
        load=struct.unpack_from('<H',entry,6)[0]
        require(entry[0]==0x88 and entry[1]==0 and entry[2:6]==b'\0\0\0\0'
                and (load==sectors if sectors<=65535 else load in (0,1))
                and records['efi.img'][0][0]==struct.unpack_from('<I',entry,8)[0]*SECTOR
                and len(records['efi.img'])==1,'El Torito does not select the exact standalone EFI FAT image')
        require(not any(entry[12:32]) and not any(catalog[64:]),'alternate El Torito entry or unsupported selection criteria refused')
        complete_hash=range_hash(fd,[(0,length)])
        require(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'ISO changed across independent extent verification')
        return {'schema_version':1,'member_count':len(expected),'all_member_bytes_compared':True,
                'efi_el_torito_verified':True,'iso_bytes':length,'iso_sha256':complete_hash,
                'boot_qualified':False,'production_qualified':False,'gate_closing':False}
    finally:
        os.close(fd)


def write_new(path,value):
    with Path(path).open('x',encoding='utf8') as stream:
        json.dump(value,stream,sort_keys=True,separators=(',',':'));stream.write('\n');stream.flush();os.fsync(stream.fileno())


def create_iso(source, destination, manifest, policy=None):
    """Package separately signed optical UKI and unchanged installed artifacts."""
    if policy is None:
        import boot_policy as policy
    from assembly_storage import require_ext4
    source,destination=Path(source),Path(destination)
    require_ext4(destination)
    for directory in (source,destination):
        require(directory.is_absolute() and str(directory)==os.path.normpath(directory),'canonical optical build directories required')
        for path in (directory,*directory.parents):
            info=path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                    'optical source/output ancestors must be protected root-owned directories')
    release=manifest['release']
    require(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}',release),'bounded release basename required')
    names=['root.ext4','root.verity','slot-a.efi','slot-b.efi','bootloader.efi','secureboot.cer',
           'release.json','release.sig','packages.lock']
    if manifest['environment']=='production':names.append('release-trust.json')
    members={};witnesses={}
    for name in [*names,'slot-optical.efi']:
        members[name],witnesses[name]=seal(source/name)
    root_bytes=(6144 if manifest['edition']=='desktop' else 4096)*MIB
    require(members['root.ext4']['bytes']==root_bytes and 4096<=members['root.verity']['bytes']<=64*MIB,
            'optical root/hash geometry differs from actual supported edition')
    for entry in manifest['artifacts']:
        require(members.get(entry['name'])=={'bytes':entry['bytes'],'sha256':entry['sha256']},
                'optical installed artifact differs from signed manifest')
    target=destination/(release+'.iso');report=destination/'optical-media.json'
    require(not os.path.lexists(target) and not os.path.lexists(report),'existing optical output refuses replacement')
    needed=sum(members[name]['bytes'] for name in names)+512*MIB+2*1024**3
    require(shutil.disk_usage(destination).free>=needed,'observed optical assembly space lacks exact members, EFI image and2GiB headroom')
    with tempfile.TemporaryDirectory(prefix='.optical-public-',dir=destination) as temporary:
        scratch=Path(temporary);certificate=scratch/'secureboot.pem'
        run('openssl','x509','-inform','DER','-in',source/'secureboot.cer','-out',certificate)
        boot_record=policy.verify_uki(source/'slot-optical.efi','optical',b'',certificate)
        sections=policy.read_sections(source/'slot-optical.efi')
        require(sections['.cmdline'].rstrip(b'\0')==policy.command_line(manifest['root_hash'],'optical',manifest['edition']).encode(),
                'signed optical UKI does not bind exact verity root and optical discovery policy')
        fat=scratch/'efi.img'
        with fat.open('xb') as stream:stream.truncate(512*MIB)
        run('mkfs.vfat','-F','32','-n','LUMAOPTICAL',fat)
        for name in ('::/EFI','::/EFI/BOOT'):run('mmd','-i',fat,name)
        run('mcopy','-i',fat,source/'slot-optical.efi','::/EFI/BOOT/BOOTX64.EFI')
        embedded=scratch/'embedded-optical.efi'
        run('mcopy','-i',fat,'::/EFI/BOOT/BOOTX64.EFI',embedded)
        require(seal(embedded)[0]==members['slot-optical.efi'],'EFI FAT contains a substituted optical UKI')
        inputs={name:members[name] for name in names};inputs['efi.img']=seal(fat)[0]
        build_iso(target,{**{name:source/name for name in names},'efi.img':fat})
        checked=verify_iso(target,inputs)
        for name,expected in witnesses.items():
            require(identity((source/name).lstat())==expected and seal(source/name)[0]==members[name],
                    'sealed optical input changed across packaging')
        checked.update({'purpose':'luma-optical-live-installer-v1','image':target.name,'edition':manifest['edition'],
            'root_hash':manifest['root_hash'],'optical_uki_sha256':members['slot-optical.efi']['sha256'],
            'optical_uki_signature_verified':True,'installed_admin_pcr_approval':boot_record['pcr_approval'],
            'installed_release_schema_unchanged':True,'installed_desktop':False,'members':inputs})
        write_new(report,checked)
        return checked


def build_iso(target, members):
    """Closed new-file ISO construction also used by tiny genuine tool tests."""
    require(not os.path.lexists(target),'existing ISO output refuses replacement')
    require('efi.img' in members and 1<len(members)<=16,'closed EFI and data inventory required')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,30}',name) for name in members),'ordinary flat optical names required')
    # -e alone creates the EFI validation platform, not a legacy BIOS entry.
    # Graft only explicit regular files; no source tree or symlink traversal.
    for path in members.values():seal(path)
    fd=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        initial=os.fstat(fd)
        # One primary namespace only: no Rock Ridge, Joliet or symlink metadata
        # can redirect the kernel to bytes different from the extent checker.
        run('xorriso','-as','mkisofs','--norock','-iso-level','3','-relaxed-filenames','-allow-lowercase',
            '-allow-multidot','-V',VOLUME.decode(),'-c','boot.catalog','-e','efi.img','-no-emul-boot',
            '-o','-','-graft-points',
            *(name+'='+str(path) for name,path in sorted(members.items())),output_fd=fd)
        os.fsync(fd);now=os.fstat(fd)
        require((now.st_dev,now.st_ino,now.st_nlink)==(initial.st_dev,initial.st_ino,1)
                and identity(now)==identity(Path(target).lstat()),'new ISO output object substituted')
    finally:
        os.close(fd)
