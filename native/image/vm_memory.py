"""Read-only Linux host RAM admission for disposable VM evaluation.

This is an observation, not a reservation, cgroup admission or a guarantee
against competing allocations. Swap must not substitute for physical RAM.
"""
from pathlib import Path
import re

MIB = 1024 ** 2
# QEMU/TCG overhead, page cache and host services need room beyond guest RAM.
HOST_RESERVE = 2048 * MIB


def available_memory(text):
    if len(text) > 65536:
        raise ValueError('oversized host memory observation')
    fields = {}
    for line in text.splitlines():
        key = line.partition(':')[0]
        if key not in ('MemTotal', 'MemAvailable'):
            continue
        match = re.fullmatch(r'(MemTotal|MemAvailable):\s+([0-9]+) kB\s*', line)
        if match is None or key in fields:
            raise ValueError('invalid or duplicate host memory observation')
        fields[key] = int(match[2]) * 1024
    if (set(fields) != {'MemTotal', 'MemAvailable'}
            or not 0 <= fields['MemAvailable'] <= fields['MemTotal']
            or fields['MemTotal'] <= 0):
        raise ValueError('missing or inconsistent host memory observation')
    return fields['MemAvailable']


def check_memory(memory_mib, text):
    if type(memory_mib) is not int or memory_mib not in (4096, 6144):
        raise ValueError('unsupported test memory fixture')
    available = available_memory(text)
    required = memory_mib * MIB + HOST_RESERVE
    if available < required:
        raise RuntimeError(
            f'VM host RAM admission refused: available={available} bytes, '
            f'guest={memory_mib * MIB} bytes, reserve={HOST_RESERVE} bytes; '
            'free host RAM or use a larger test host; swap is not capacity')
    return {'guest_memory_mib': memory_mib, 'host_available_bytes': available,
            'host_reserve_bytes': HOST_RESERVE, 'reservation': False}


def admit_guest(memory_mib):
    # Fixed kernel source, bounded read; do not accept a caller-supplied number
    # or mutate global WSL, swap or unrelated workloads to make admission pass.
    with Path('/proc/meminfo').open(encoding='ascii') as stream:
        text = stream.read(65537)
    return check_memory(memory_mib, text)
