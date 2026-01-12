#!/usr/bin/env python3
"""
MZNE - EXE Analyzer
A tool to analyze DOS/Win16 EXE files and extract interrupt usage.
"""

import sys
import os
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Optional, Tuple, Dict, Any
import struct

# Interrupt names and descriptions for Windows 1.0 / DOS
INT_NAMES = {
    0x00: ("Divide Error", "Division by zero or overflow"),
    0x01: ("Single Step", "Debug trap flag"),
    0x02: ("NMI", "Non-maskable interrupt"),
    0x03: ("Breakpoint", "Debug breakpoint"),
    0x04: ("Overflow", "INTO instruction overflow"),
    0x05: ("Print Screen", "Print screen key handler"),
    0x06: ("Invalid Opcode", "Undefined instruction"),
    0x07: ("Coprocessor Not Available", "Math coprocessor error"),
    0x08: ("Timer", "IRQ0 - System timer"),
    0x09: ("Keyboard", "IRQ1 - Keyboard interrupt"),
    0x0A: ("Reserved", "IRQ2 - Cascade for slave PIC"),
    0x0B: ("Serial Port", "IRQ3 - COM2/COM4"),
    0x0C: ("Serial Port", "IRQ4 - COM1/COM3"),
    0x0D: ("Hard Disk", "IRQ5 - Hard disk / LPT2"),
    0x0E: ("Floppy Disk", "IRQ6 - Floppy disk controller"),
    0x0F: ("Parallel Port", "IRQ7 - LPT1"),
    0x10: ("Video BIOS", "Video services (EGA/VGA/CGA)"),
    0x11: ("Equipment Check", "Get equipment list"),
    0x12: ("Memory Size", "Get conventional memory size"),
    0x13: ("Disk BIOS", "Disk I/O services"),
    0x14: ("Serial Port", "Serial communications"),
    0x15: ("System Services", "Misc system services (APM, etc.)"),
    0x16: ("Keyboard BIOS", "Keyboard services"),
    0x17: ("Printer", "Printer services"),
    0x18: ("ROM BASIC", "ROM BASIC entry point"),
    0x19: ("Bootstrap", "Reboot system"),
    0x1A: ("Timer/RTC", "Real-time clock services"),
    0x1B: ("Keyboard Break", "Ctrl+Break handler"),
    0x1C: ("Timer Tick", "Timer interrupt handler"),
    0x1D: ("Video Parameters", "Video parameter table"),
    0x1E: ("Disk Parameters", "Disk parameter table"),
    0x1F: ("Font Data", "Graphics font table"),
    0x20: ("Terminate Program", "DOS program termination"),
    0x21: ("DOS Calls", "DOS function dispatcher"),
    0x22: ("Terminate Address", "Program termination handler"),
    0x23: ("Ctrl+C Handler", "Ctrl+C break handler"),
    0x24: ("Critical Error", "Critical error handler"),
    0x25: ("Absolute Disk Read", "Direct disk sector read"),
    0x26: ("Absolute Disk Write", "Direct disk sector write"),
    0x27: ("Terminate and Stay Resident", "TSR termination"),
    0x28: ("DOS Idle", "DOS idle hook"),
    0x29: ("Fast Console Output", "Fast character output"),
    0x2A: ("Network", "Network services"),
    0x2B: ("Reserved", "Reserved"),
    0x2C: ("Reserved", "Reserved"),
    0x2D: ("Reserved", "Reserved"),
    0x2E: ("Command Processor", "Command processor execution"),
    0x2F: ("Multiplex", "Windows/DOS multiplex interrupt"),
    0x30: ("DOS API", "DOS API entry point"),
    0x31: ("DPMI", "DOS Protected Mode Interface"),
    0x32: ("Reserved", "Reserved"),
    0x33: ("Mouse", "Microsoft Mouse driver services"),
    0x34: ("Floating Point", "Floating point emulation"),
    0x35: ("Reserved", "Reserved"),
    0x36: ("Reserved", "Reserved"),
    0x37: ("Reserved", "Reserved"),
    0x38: ("Reserved", "Reserved"),
    0x39: ("Reserved", "Reserved"),
    0x3A: ("Reserved", "Reserved"),
    0x3B: ("Reserved", "Reserved"),
    0x3C: ("Reserved", "Reserved"),
    0x3D: ("Reserved", "Reserved"),
    0x3E: ("Reserved", "Reserved"),
    0x3F: ("Overlay Manager", "Overlay manager services"),
}


# INT 21h DOS function calls (AH register values)
DOS_FUNCTIONS = {
    0x00: ("Terminate Program", "Exit program"),
    0x01: ("Character Input with Echo", "Read character from stdin with echo"),
    0x02: ("Character Output", "Write character to stdout"),
    0x03: ("Auxiliary Input", "Read character from COM port"),
    0x04: ("Auxiliary Output", "Write character to COM port"),
    0x05: ("Printer Output", "Write character to printer"),
    0x06: ("Direct Console I/O", "Direct console input/output"),
    0x07: ("Direct Character Input", "Read character from stdin (no echo)"),
    0x08: ("Character Input without Echo", "Read character from stdin (no echo)"),
    0x09: ("Print String", "Write string to stdout"),
    0x0A: ("Buffered Input", "Read string from stdin"),
    0x0B: ("Check Input Status", "Check if character available"),
    0x0C: ("Flush Buffer and Read", "Clear input buffer and read"),
    0x0D: ("Disk Reset", "Reset disk system"),
    0x0E: ("Select Disk", "Set default drive"),
    0x0F: ("Open File (FCB)", "Open file using FCB"),
    0x10: ("Close File (FCB)", "Close file using FCB"),
    0x11: ("Find First (FCB)", "Find first matching file"),
    0x12: ("Find Next (FCB)", "Find next matching file"),
    0x13: ("Delete File (FCB)", "Delete file using FCB"),
    0x14: ("Sequential Read (FCB)", "Read sequential record"),
    0x15: ("Sequential Write (FCB)", "Write sequential record"),
    0x16: ("Create File (FCB)", "Create file using FCB"),
    0x17: ("Rename File (FCB)", "Rename file using FCB"),
    0x19: ("Get Current Disk", "Get default drive"),
    0x1A: ("Set DTA", "Set disk transfer address"),
    0x1B: ("Get Default Drive Info", "Get default drive FAT info"),
    0x1C: ("Get Drive Info", "Get drive FAT info"),
    0x1F: ("Get Default DPB", "Get default drive parameter block"),
    0x21: ("Random Read (FCB)", "Read random record"),
    0x22: ("Random Write (FCB)", "Write random record"),
    0x23: ("Get File Size (FCB)", "Get file size"),
    0x24: ("Set Relative Record", "Set relative record number"),
    0x25: ("Set Interrupt Vector", "Set interrupt handler"),
    0x26: ("Create PSP", "Create program segment prefix"),
    0x27: ("Random Block Read (FCB)", "Read random block"),
    0x28: ("Random Block Write (FCB)", "Write random block"),
    0x29: ("Parse Filename (FCB)", "Parse filename into FCB"),
    0x2A: ("Get Date", "Get system date"),
    0x2B: ("Set Date", "Set system date"),
    0x2C: ("Get Time", "Get system time"),
    0x2D: ("Set Time", "Set system time"),
    0x2E: ("Set Verify Flag", "Set disk verify flag"),
    0x2F: ("Get DTA", "Get disk transfer address"),
    0x30: ("Get DOS Version", "Get DOS version number"),
    0x31: ("Terminate and Stay Resident", "Keep program resident"),
    0x33: ("Ctrl-Break Check", "Get/set Ctrl-Break flag"),
    0x34: ("Get InDOS Flag", "Get InDOS flag address"),
    0x35: ("Get Interrupt Vector", "Get interrupt handler address"),
    0x36: ("Get Free Disk Space", "Get disk free space"),
    0x38: ("Get Country Info", "Get country-dependent information"),
    0x39: ("Create Directory", "Create subdirectory"),
    0x3A: ("Remove Directory", "Remove subdirectory"),
    0x3B: ("Change Directory", "Change current directory"),
    0x3C: ("Create File (Handle)", "Create/truncate file"),
    0x3D: ("Open File (Handle)", "Open existing file"),
    0x3E: ("Close File (Handle)", "Close file handle"),
    0x3F: ("Read File (Handle)", "Read from file/device"),
    0x40: ("Write File (Handle)", "Write to file/device"),
    0x41: ("Delete File (Handle)", "Delete file"),
    0x42: ("Move File Pointer", "Seek in file"),
    0x43: ("Get/Set File Attributes", "Get or set file attributes"),
    0x44: ("IOCTL", "Device I/O control"),
    0x45: ("Duplicate Handle", "Duplicate file handle"),
    0x46: ("Force Duplicate Handle", "Force duplicate file handle"),
    0x47: ("Get Current Directory", "Get current directory path"),
    0x48: ("Allocate Memory", "Allocate memory block"),
    0x49: ("Free Memory", "Free memory block"),
    0x4A: ("Resize Memory", "Resize memory block"),
    0x4B: ("Load/Execute Program", "Load and execute program"),
    0x4C: ("Terminate Program", "Exit program with return code"),
    0x4D: ("Get Return Code", "Get child process return code"),
    0x4E: ("Find First File", "Find first matching file"),
    0x4F: ("Find Next File", "Find next matching file"),
    0x50: ("Set PSP", "Set program segment prefix"),
    0x51: ("Get PSP", "Get program segment prefix"),
    0x52: ("Get List of Lists", "Get DOS internal data"),
    0x53: ("Translate BPB", "Translate BIOS parameter block"),
    0x54: ("Get Verify Flag", "Get disk verify flag"),
    0x55: ("Create PSP", "Create program segment prefix"),
    0x56: ("Rename File", "Rename file"),
    0x57: ("Get/Set File Date/Time", "Get or set file date/time"),
    0x58: ("Get/Set Memory Strategy", "Get or set memory allocation strategy"),
    0x59: ("Get Extended Error", "Get extended error information"),
    0x5A: ("Create Temporary File", "Create temporary file"),
    0x5B: ("Create New File", "Create new file (fail if exists)"),
    0x5C: ("Lock/Unlock File", "Lock or unlock file region"),
    0x5D: ("Critical Error Handler", "Set critical error handler"),
    0x5E: ("Network Functions", "Network redirection functions"),
    0x5F: ("Network Functions", "Network redirection functions"),
    0x60: ("Canonicalize Path", "Canonicalize file path"),
    0x62: ("Get PSP Address", "Get program segment prefix address"),
    0x65: ("Get Extended Country Info", "Get extended country information"),
    0x66: ("Get/Set Code Page", "Get or set code page"),
    0x67: ("Set Handle Count", "Set maximum file handles"),
    0x68: ("Commit File", "Flush file buffers"),
    0x6C: ("Extended Open File", "Extended file open"),
}

# INT 3Fh Overlay Manager function calls (AH register values)
OVERLAY_FUNCTIONS = {
    0x00: ("Load Overlay", "Load overlay segment into memory"),
    0x01: ("Get Overlay Info", "Get overlay information"),
    0x02: ("Release Overlay", "Release overlay from memory"),
    0x03: ("Call Overlay", "Call overlay routine"),
    0x04: ("Get Overlay State", "Get overlay state information"),
    0x05: ("Set Overlay Path", "Set overlay file path"),
    0x06: ("Get Overlay Path", "Get overlay file path"),
    0x07: ("Register Overlay", "Register overlay segment"),
    0x08: ("Unregister Overlay", "Unregister overlay segment"),
    0x09: ("Find Overlay", "Find overlay by name"),
    0x0A: ("Get Overlay Count", "Get number of loaded overlays"),
    0x0B: ("Get Overlay List", "Get list of loaded overlays"),
    0x0C: ("Set Overlay Callback", "Set overlay callback function"),
    0x0D: ("Get Overlay Callback", "Get overlay callback function"),
    0x0E: ("Flush Overlays", "Flush all overlays from memory"),
    0x0F: ("Get Overlay Size", "Get overlay segment size"),
    0x10: ("Load Overlay by Name", "Load overlay by filename"),
    0x11: ("Get Overlay Address", "Get overlay segment address"),
    0x12: ("Set Overlay Priority", "Set overlay loading priority"),
    0x13: ("Get Overlay Priority", "Get overlay loading priority"),
    0x14: ("Lock Overlay", "Lock overlay in memory"),
    0x15: ("Unlock Overlay", "Unlock overlay from memory"),
    0x16: ("Get Overlay Status", "Get overlay status flags"),
    0x17: ("Set Overlay Status", "Set overlay status flags"),
    0x18: ("Get Overlay Error", "Get last overlay error"),
    0x19: ("Clear Overlay Error", "Clear overlay error state"),
    0x1A: ("Get Overlay Version", "Get overlay manager version"),
    0x1B: ("Reserve Overlay Memory", "Reserve memory for overlay"),
    0x1C: ("Free Overlay Memory", "Free reserved overlay memory"),
    0x1D: ("Get Overlay Statistics", "Get overlay usage statistics"),
    0x1E: ("Set Overlay Options", "Set overlay manager options"),
    0x1F: ("Get Overlay Options", "Get overlay manager options"),
}


def get_int_name(int_num: int) -> str:
    """Get interrupt name and description."""
    if int_num in INT_NAMES:
        name, desc = INT_NAMES[int_num]
        return f"{name} - {desc}"
    return "Unknown interrupt"


def get_dos_function_name(ah_value: Optional[int]) -> str:
    """Get DOS function name for INT 21h."""
    if ah_value is None:
        return "unknown function"
    if ah_value in DOS_FUNCTIONS:
        name, desc = DOS_FUNCTIONS[ah_value]
        return f"{name} ({desc})"
    return f"function 0x{ah_value:02X}"


def get_overlay_function_name(ah_value: Optional[int]) -> str:
    """Get Overlay Manager function name for INT 3Fh."""
    if ah_value is None:
        return "unknown function"
    if ah_value in OVERLAY_FUNCTIONS:
        name, desc = OVERLAY_FUNCTIONS[ah_value]
        return f"{name} ({desc})"
    return f"function 0x{ah_value:02X}"


def extract_ah_value(data: bytes, offset: int, lookback: int = 30) -> Optional[int]:
    """
    Try to extract AH value from context before INT instruction.
    Looks for common patterns like MOV AH, XX.
    """
    start = max(0, offset - lookback)
    context = data[start:offset]
    context_offset = start
    
    # Look backwards for MOV AH, imm8 pattern: B4 XX (MOV AH, XX)
    # Grab most recent MOV AH found
    for i in range(len(context) - 1, -1, -1):
        if context[i] == 0xB4:  # MOV AH, imm8
            if i + 1 < len(context):
                # Check if there are any other instructions between this MOV and the INT
                # use most recent MOV AH found
                return context[i + 1]
    
    # Look for MOV AX, imm16 pattern: B8 XX XX (MOV AX, imm16)
    # extract AH from the high byte
    for i in range(len(context) - 2, -1, -1):
        if context[i] == 0xB8:  # MOV AX, imm16
            if i + 2 < len(context):
                # AH is the high byte (second byte of the immediate)
                return context[i + 2]
    
    return None


def parse_mz_header(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse MZ (DOS) executable header."""
    if len(data) < 0x1C:
        return None
    
    # Check MZ signature
    if data[0:2] != b'MZ':
        return None
    
    # Parse MZ header fields
    header = {}
    header['signature'] = data[0:2].decode('ascii')
    header['last_page_bytes'] = struct.unpack('<H', data[2:4])[0]
    header['pages'] = struct.unpack('<H', data[4:6])[0]
    header['relocations'] = struct.unpack('<H', data[6:8])[0]
    header['header_paragraphs'] = struct.unpack('<H', data[8:10])[0]
    header['min_paragraphs'] = struct.unpack('<H', data[10:12])[0]
    header['max_paragraphs'] = struct.unpack('<H', data[12:14])[0]
    header['initial_ss'] = struct.unpack('<H', data[14:16])[0]
    header['initial_sp'] = struct.unpack('<H', data[16:18])[0]
    header['checksum'] = struct.unpack('<H', data[18:20])[0]
    header['initial_ip'] = struct.unpack('<H', data[20:22])[0]
    header['initial_cs'] = struct.unpack('<H', data[22:24])[0]
    header['reloc_table_offset'] = struct.unpack('<H', data[24:26])[0]
    header['overlay_number'] = struct.unpack('<H', data[26:28])[0]
    
    # Calculate file size
    header['file_size'] = (header['pages'] - 1) * 512 + header['last_page_bytes']
    if header['last_page_bytes'] == 0:
        header['file_size'] = header['pages'] * 512
    
    # Check for NE header (Windows executable)
    # NE header can be at various locations, search for it
    header_size = header['header_paragraphs'] * 16
    ne_offset = None
    
    # First try the common location: after MZ header
    test_offset = header_size
    if test_offset < len(data) and data[test_offset:test_offset+2] == b'NE':
        ne_offset = test_offset
    else:
        # Search for NE signature in the file (usually within first few KB)
        search_limit = min(len(data), 8192)
        for i in range(header_size, search_limit, 2):
            if i + 2 <= len(data) and data[i:i+2] == b'NE':
                ne_offset = i
                break
    
    if ne_offset is not None:
        header['ne_offset'] = ne_offset
        header['has_ne'] = True
    else:
        header['has_ne'] = False
    
    return header


def parse_ne_header(data: bytes, ne_offset: int) -> Optional[Dict[str, Any]]:
    """Parse NE (New Executable / Windows 16-bit) header."""
    if ne_offset + 0x40 > len(data):
        return None
    
    if data[ne_offset:ne_offset+2] != b'NE':
        return None
    
    header = {}
    header['signature'] = data[ne_offset:ne_offset+2].decode('ascii')
    header['linker_version'] = data[ne_offset+2]
    header['linker_revision'] = data[ne_offset+3]
    header['entry_table_offset'] = struct.unpack('<H', data[ne_offset+4:ne_offset+6])[0]
    header['entry_table_length'] = struct.unpack('<H', data[ne_offset+6:ne_offset+8])[0]
    header['file_load_crc'] = struct.unpack('<L', data[ne_offset+8:ne_offset+12])[0]
    header['program_flags'] = struct.unpack('<H', data[ne_offset+12:ne_offset+14])[0]
    header['app_flags'] = struct.unpack('<H', data[ne_offset+14:ne_offset+16])[0]
    header['auto_data_segment'] = struct.unpack('<H', data[ne_offset+16:ne_offset+18])[0]
    header['initial_heap_size'] = struct.unpack('<H', data[ne_offset+18:ne_offset+20])[0]
    header['initial_stack_size'] = struct.unpack('<H', data[ne_offset+20:ne_offset+22])[0]
    header['initial_cs'] = struct.unpack('<H', data[ne_offset+22:ne_offset+24])[0]
    header['initial_ip'] = struct.unpack('<H', data[ne_offset+24:ne_offset+26])[0]
    header['initial_ss'] = struct.unpack('<H', data[ne_offset+26:ne_offset+28])[0]
    header['initial_sp'] = struct.unpack('<H', data[ne_offset+28:ne_offset+30])[0]
    header['segment_count'] = struct.unpack('<H', data[ne_offset+30:ne_offset+32])[0]
    header['module_reference_count'] = struct.unpack('<H', data[ne_offset+32:ne_offset+34])[0]
    header['nonresident_names_size'] = struct.unpack('<H', data[ne_offset+34:ne_offset+36])[0]
    header['segment_table_offset'] = struct.unpack('<H', data[ne_offset+36:ne_offset+38])[0]
    header['resource_table_offset'] = struct.unpack('<H', data[ne_offset+38:ne_offset+40])[0]
    header['resident_names_offset'] = struct.unpack('<H', data[ne_offset+40:ne_offset+42])[0]
    header['module_reference_offset'] = struct.unpack('<H', data[ne_offset+42:ne_offset+44])[0]
    header['imported_names_offset'] = struct.unpack('<H', data[ne_offset+44:ne_offset+46])[0]
    header['nonresident_names_offset'] = struct.unpack('<L', data[ne_offset+46:ne_offset+50])[0]
    header['movable_entries'] = struct.unpack('<H', data[ne_offset+50:ne_offset+52])[0]
    header['sector_alignment_shift'] = struct.unpack('<H', data[ne_offset+52:ne_offset+54])[0]
    header['resource_entries'] = struct.unpack('<H', data[ne_offset+54:ne_offset+56])[0]
    header['target_os'] = struct.unpack('<B', data[ne_offset+56:ne_offset+57])[0]
    header['other_exe'] = struct.unpack('<B', data[ne_offset+57:ne_offset+58])[0]
    header['version_info_offset'] = struct.unpack('<H', data[ne_offset+58:ne_offset+60])[0]
    header['version_info_length'] = struct.unpack('<H', data[ne_offset+60:ne_offset+62])[0]
    header['fast_load_offset'] = struct.unpack('<H', data[ne_offset+62:ne_offset+64])[0]
    header['fast_load_length'] = struct.unpack('<H', data[ne_offset+64:ne_offset+66])[0]
    header['reserved'] = struct.unpack('<H', data[ne_offset+66:ne_offset+68])[0]
    header['expected_windows_version'] = struct.unpack('<H', data[ne_offset+68:ne_offset+70])[0]
    
    # Decode target OS
    os_map = {
        0x00: "Unknown",
        0x01: "OS/2",
        0x02: "Windows",
        0x03: "European MS-DOS 4.x",
        0x04: "Windows 386",
        0x05: "BOSS (Borland Operating System Services)",
    }
    header['target_os_name'] = os_map.get(header['target_os'], f"Unknown (0x{header['target_os']:02X})")
    
    # Decode program flags
    program_flags = []
    flags = header['program_flags']
    if flags & 0x0001: program_flags.append("Long filename support")
    if flags & 0x0002: program_flags.append("2.x protected mode")
    if flags & 0x0004: program_flags.append("2.x proportional font")
    if flags & 0x0008: program_flags.append("Gangload area")
    header['program_flags_list'] = program_flags if program_flags else ["None"]
    
    # Decode application flags
    app_flags = []
    flags = header['app_flags']
    if flags & 0x0001: app_flags.append("Full screen (not compatible with Windows)")
    if flags & 0x0002: app_flags.append("Compatible with Windows PIF")
    if flags & 0x0004: app_flags.append("Windows PIF application")
    if flags & 0x0008: app_flags.append("OS/2 family application")
    if flags & 0x0010: app_flags.append("OS/2 family application")
    if flags & 0x0080: app_flags.append("Unknown")
    if flags & 0x2000: app_flags.append("DLL")
    if flags & 0x8000: app_flags.append("Not a Windows application")
    header['app_flags_list'] = app_flags if app_flags else ["None"]
    
    return header


def scan_interrupts(data: bytes) -> dict:
    """
    Scan binary data for INT instructions and extract interrupt usage.
    Returns a dictionary mapping interrupt numbers to lists of (offset, ah_value) tuples.
    """
    interrupts = defaultdict(list)
    
    i = 0
    while i < len(data) - 1:
        if data[i] == 0xCD:  # INT opcode
            int_num = data[i + 1]
            offset = i
            
            # Try to extract AH value from context
            ah_value = extract_ah_value(data, offset)
            
            # Special case for INT 3Fh: check if function code is embedded
            # right after the INT instruction (common in jump tables/import tables)
            if int_num == 0x3F and ah_value is None and i + 2 < len(data):
                # Check if the byte after INT 3Fh looks like a function code
                # (reasonable range: 0x00-0x1F for overlay functions)
                potential_func = data[i + 2]
                if potential_func <= 0x1F:
                    # In jump tables, the pattern is often: CD 3F XX [2 bytes] 01
                    # or just CD 3F XX followed by data
                    # If the next byte is a reasonable function code, use it
                    ah_value = potential_func
            
            interrupts[int_num].append((offset, ah_value))
            i += 2
        else:
            i += 1
    
    return interrupts

        
def process_exe(file_path):
    """Process a single EXE file and extract interrupt usage."""
    path = Path(file_path)
    
    if not path.exists():
        print(f"Error: File not found: {file_path}")
        return False
    
    if not path.is_file():
        print(f"Error: Not a file: {file_path}")
        return False
    
    # Read all bytes
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return False
    
    # Get file info
    size = len(data)
    
    print(f"\n{'='*70}")
    print(f"Processing: {path.name}")
    print(f"  Path: {path.absolute()}")
    print(f"  Size: {size:,} bytes ({size / 1024:.2f} KB)")
    print(f"{'='*70}")
    
    # Parse headers
    mz_header = parse_mz_header(data)
    ne_header = None
    
    if mz_header:
        print(f"\n📋 MZ HEADER (DOS Executable)")
        print("-" * 70)
        print(f"  Signature: {mz_header['signature']}")
        print(f"  Bytes in last page: {mz_header['last_page_bytes']}")
        print(f"  Pages in file: {mz_header['pages']}")
        print(f"  Relocations: {mz_header['relocations']}")
        print(f"  Header size (paragraphs): {mz_header['header_paragraphs']} ({mz_header['header_paragraphs'] * 16} bytes)")
        print(f"  Minimum paragraphs: {mz_header['min_paragraphs']} ({mz_header['min_paragraphs'] * 16} bytes)")
        print(f"  Maximum paragraphs: {mz_header['max_paragraphs']} ({mz_header['max_paragraphs'] * 16} bytes)")
        print(f"  Initial SS: 0x{mz_header['initial_ss']:04X}")
        print(f"  Initial SP: 0x{mz_header['initial_sp']:04X} ({mz_header['initial_sp']})")
        print(f"  Checksum: 0x{mz_header['checksum']:04X}")
        print(f"  Initial IP: 0x{mz_header['initial_ip']:04X}")
        print(f"  Initial CS: 0x{mz_header['initial_cs']:04X}")
        print(f"  Relocation table offset: 0x{mz_header['reloc_table_offset']:04X}")
        print(f"  Overlay number: {mz_header['overlay_number']}")
        print(f"  Calculated file size: {mz_header['file_size']:,} bytes")
        
        if mz_header['has_ne']:
            ne_header = parse_ne_header(data, mz_header['ne_offset'])
            if ne_header:
                print(f"\n📋 NE HEADER (Windows 16-bit Executable)")
                print("-" * 70)
                print(f"  Signature: {ne_header['signature']}")
                print(f"  Linker version: {ne_header['linker_version']}.{ne_header['linker_revision']}")
                print(f"  Entry table offset: 0x{ne_header['entry_table_offset']:04X}")
                print(f"  Entry table length: {ne_header['entry_table_length']} bytes")
                print(f"  File load CRC: 0x{ne_header['file_load_crc']:08X}")
                print(f"  Program flags: 0x{ne_header['program_flags']:04X} - {', '.join(ne_header['program_flags_list'])}")
                print(f"  Application flags: 0x{ne_header['app_flags']:04X} - {', '.join(ne_header['app_flags_list'])}")
                print(f"  Auto data segment: {ne_header['auto_data_segment']}")
                print(f"  Initial heap size: {ne_header['initial_heap_size']} bytes")
                print(f"  Initial stack size: {ne_header['initial_stack_size']} bytes")
                print(f"  Initial CS: 0x{ne_header['initial_cs']:04X}")
                print(f"  Initial IP: 0x{ne_header['initial_ip']:04X}")
                print(f"  Initial SS: 0x{ne_header['initial_ss']:04X}")
                print(f"  Initial SP: 0x{ne_header['initial_sp']:04X} ({ne_header['initial_sp']})")
                print(f"  Segment count: {ne_header['segment_count']}")
                print(f"  Module reference count: {ne_header['module_reference_count']}")
                print(f"  Non-resident names size: {ne_header['nonresident_names_size']} bytes")
                print(f"  Segment table offset: 0x{ne_header['segment_table_offset']:04X}")
                print(f"  Resource table offset: 0x{ne_header['resource_table_offset']:04X}")
                print(f"  Resident names offset: 0x{ne_header['resident_names_offset']:04X}")
                print(f"  Module reference offset: 0x{ne_header['module_reference_offset']:04X}")
                print(f"  Imported names offset: 0x{ne_header['imported_names_offset']:04X}")
                print(f"  Non-resident names offset: 0x{ne_header['nonresident_names_offset']:08X}")
                print(f"  Movable entries: {ne_header['movable_entries']}")
                print(f"  Sector alignment shift: {ne_header['sector_alignment_shift']}")
                print(f"  Resource entries: {ne_header['resource_entries']}")
                print(f"  Target OS: {ne_header['target_os_name']} (0x{ne_header['target_os']:02X})")
                print(f"  Expected Windows version: {ne_header['expected_windows_version'] >> 8}.{ne_header['expected_windows_version'] & 0xFF}")
    else:
        print(f"\n⚠️  Not a valid MZ executable")
    
    # Scan for interrupts
    interrupts = scan_interrupts(data)
    
    # Report all interrupts found
    print("INTERRUPT USAGE ANALYSIS")
    print("-" * 70)
    
    if not interrupts:
        print("No interrupt calls detected in this file.")
    else:
        for int_num in sorted(interrupts.keys()):
            calls = interrupts[int_num]
            int_hex = f"INT {int_num:02X}h"
            int_name = get_int_name(int_num)
            
            print(f"\n{int_hex} - {int_name}")
            print(f"  Total calls: {len(calls)}")
            print(f"  Call sites:")
            
            for offset, ah_value in calls:
                if int_num == 0x21:  # INT 21h - show DOS function name
                    func_name = get_dos_function_name(ah_value)
                    ah_str = f"AH=0x{ah_value:02X}" if ah_value is not None else "AH=unknown"
                    print(f"    Offset 0x{offset:06X} ({offset:6d}) - {ah_str} - {func_name}")
                elif int_num == 0x3F:  # INT 3Fh - show Overlay Manager function name
                    func_name = get_overlay_function_name(ah_value)
                    ah_str = f"AH=0x{ah_value:02X}" if ah_value is not None else "AH=unknown"
                    print(f"    Offset 0x{offset:06X} ({offset:6d}) - {ah_str} - {func_name}")
                else:
                    ah_str = f"AH=0x{ah_value:02X}" if ah_value is not None else "AH=unknown"
                    print(f"    Offset 0x{offset:06X} ({offset:6d}) - {ah_str}")
    
    # Summary
    total_calls = sum(len(v) for v in interrupts.values())
    print(f"SUMMARY")
    print("-" * 70)
    print(f"  Unique interrupts: {len(interrupts)}")
    print(f"  Total INT calls: {total_calls}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="MZNE - EXE Analyzer. Accepts and processes EXE files from command line."
    )
    parser.add_argument(
        "exes",
        nargs="+",
        help="One or more EXE file paths to process"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if not args.exes:
        parser.print_help()
        sys.exit(1)
    
    success_count = 0
    for exe_path in args.exes:
        if process_exe(exe_path):
            success_count += 1
    
    print(f"\nProcessed {success_count}/{len(args.exes)} file(s) successfully.")
    
    if success_count == len(args.exes):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
