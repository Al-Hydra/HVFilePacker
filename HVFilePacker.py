from binary_reader import *
import lzokay
import os, sys
import json
from zlib import crc32
import numpy as np
from time import perf_counter
#from cProfile import Profile
class HVP(BrStruct):
    def __init__(self):
        self.Signature = 0
        self.EntryCount = 0
        self.CRC32 = 0
        self.Name = ""
        self.Entries = []
        self.Endianness = "little"
    
    def __br_write__(self, br: BinaryReader) -> None:
        print(br.get_endian())
            
        br.write_uint32(262144)
        br.write_uint32(0)
        br.write_uint32(self.EntryCount)
        
        header_buffer = BinaryReader(endianness=br.get_endian(), encoding="cp932")
        data_buffer = BinaryReader(endianness=br.get_endian(), encoding="cp932")
        
        entries_size = br.size() + 4 + 24 * self.EntryCount
        
        for entry in self.Entries:
            if isinstance(entry, HVPDirectory):
                header_buffer.write_uint32(entry.CRC32)
                header_buffer.write_uint16(4)
                header_buffer.pad(10)
                header_buffer.write_uint32(entry.EntryCount)
                header_buffer.write_uint32(entry.FirstEntryIndex)
            else:
                header_buffer.write_uint32(entry.CRC32)
                header_buffer.write_uint32(entry.Type)
                header_buffer.write_uint32(entry.DataCRC32)
                header_buffer.write_uint32(entry.UncompressedSize)
                header_buffer.write_uint32(entries_size + data_buffer.size())
                header_buffer.write_uint32(entry.CompressedSize)
                data_buffer.extend(entry.Data)
        
        header_crc = crc32(bytes(header_buffer.buffer()))
        
        br.write_uint32(header_crc)
        br.extend(header_buffer.buffer())
        br.extend(data_buffer.buffer())
    

class HVPDirectory:
    def __init__(self):
        self.CRC32 = 0
        self.Type = 4
        self.EntryCount = 0
        self.FirstEntryIndex = 0
        self.SubEntries = []

class HVPEntry:
    def __init__(self):
        self.CRC32 = 0
        self.Name = ""
        self.Type = 0
        self.DataCRC32 = 0
        self.CompressedSize = 0
        self.UncompressedSize = 0
        self.Data = None


def obscureCRC32(byte_array):
    # Main checksum initialization
    checksum = 0
    length = len(byte_array)
    
    # Fast processing in chunks of 4 bytes using numpy, if available
    if length >= 4:
        # Use numpy's view method to treat the byte array as an array of uint32
        array_view = np.frombuffer(byte_array, dtype=np.uint32, count=length // 4)
        checksum += array_view.sum()
    
    # Directly process any remaining bytes (up to 3 bytes)
    remainder = length % 4
    if remainder:
        remaining_bytes = byte_array[-remainder:]
        for i, byte in enumerate(remaining_bytes):
            checksum += byte << (i * 8)

    # Return checksum as a 32-bit unsigned integer
    return checksum & 0xFFFFFFFF


def read_hvp(hvp_path):
    with open(hvp_path, "rb") as f:
        file_bytes = f.read()
        
    br = BinaryReader(file_bytes, Endian.LITTLE, "cp932")

    hvp = HVP()

    hvp.Signature = br.read_uint32()
    if hvp.Signature == 1024:
        br.set_endian(Endian.BIG)
        hvp.Endianness = "big"

    br.seek(4, 1)
    hvp.EntryCount = br.read_uint32()
    hvp.CRC32 = br.read_uint32()
    
    print(br.get_endian())


    for i in range(hvp.EntryCount):
        CRC32_code = br.read_uint32()
        entry_type = br.read_uint16()
        br.seek(2,1)
        
        if entry_type == 4:
            br.seek(8,1)
            hvp_dir = HVPDirectory()
            hvp_dir.CRC32 = CRC32_code
            hvp_dir.EntryCount = br.read_uint32()
            hvp_dir.FirstEntryIndex = br.read_uint32()
            
            hvp.Entries.append(hvp_dir)
        
        else:
            entry = HVPEntry()
            entry.CRC32 = CRC32_code
            entry.Type = entry_type
            entry.DataCRC32 = br.read_uint32()
            entry.UncompressedSize = br.read_uint32()
            offset = br.read_uint32()
            entry.CompressedSize = br.read_uint32()
            pos = br.pos()
            
            br.seek(offset)
            entry.Data = br.read_bytes(entry.CompressedSize)
            br.seek(pos)

            hvp.Entries.append(entry)
            
    return hvp



if hasattr(sys, 'argv') and sys.argv[0]:
    # If the application is compiled with Nuitka
    current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    # If the application is running as a script
    current_dir = os.path.dirname(os.path.realpath(__file__))

# Construct the path to the hashes.json file
hashes_path = os.path.join(current_dir, "hashes.json")


hash_dict = json.load(open(hashes_path, "r"))

repack_info_dict = {}

def make_dirs(hvp, entry, abs_path, internal_path = ""):
    
    if isinstance(entry, HVPDirectory):
        
        dir_name = hash_dict.get(str(entry.CRC32), str(entry.CRC32))        
        abs_path = os.path.join(abs_path, dir_name)
        os.makedirs(abs_path, exist_ok=True)
        internal_path = os.path.join(internal_path, dir_name)
        
        entry.SubEntries = hvp.Entries[entry.FirstEntryIndex: entry.FirstEntryIndex + entry.EntryCount]
        
        repack_info_dict[hvp.Entries.index(entry)] = [hex(entry.CRC32), internal_path]
        
        for subentry in entry.SubEntries:
            make_dirs(hvp, subentry, abs_path, internal_path)
    else:
        file_name = hash_dict.get(str(entry.CRC32), f"{entry.CRC32}.bin")
            
        file_path = os.path.join(abs_path, file_name)
        
        internal_path = os.path.join(internal_path, file_name)
        
        #attempt to decompress the file 
        if entry.Type == 1:
            entry.Data = lzokay.decompress(entry.Data)
            entry.Type = 0
        
        repack_info_dict[hvp.Entries.index(entry)] = [hex(entry.CRC32), internal_path]
        
        with open(file_path, "wb") as f:
            f.write(entry.Data)
    
    
def repack_hvp(hvp, unpacked_hvp_folder, new_hvp_path):
        
    repack_info = json.load(open(f"{unpacked_hvp_folder}\\repack_info.json", "r"))
    

    for i, (entry) in enumerate(hvp.Entries):
        
        if entry.Type == 4:
            continue
        
        elif entry.Type in [0, 1]:
            #get the file path from the repack_info_dict
            file_info = repack_info[str(i)]
            file_crc = file_info[0]
            file_path = file_info[1]
            
            abs_path = os.path.join(unpacked_hvp_folder, file_path)
            
            if abs_path is not None:
                with open(abs_path, "rb") as f:
                    entry.Data = f.read()
                
                entry.UncompressedSize = entry.CompressedSize = len(entry.Data)
                entry.DataCRC32 = obscureCRC32(entry.Data)
                entry.Type = 0
        
    
    if hvp.Endianness == "big":
        br = BinaryReader(endianness=Endian.BIG, encoding="cp932")
    else:
        br = BinaryReader(endianness=Endian.LITTLE, encoding="cp932")
    br.write_struct(hvp)
    
    with open(new_hvp_path, "wb") as f:
        f.write(bytes(br.buffer()))


def repack_compress_hvp(hvp, unpacked_hvp_folder, new_hvp_path):
            
        repack_info = json.load(open(f"{unpacked_hvp_folder}\\repack_info.json", "r"))
        
    
        for i, (entry) in enumerate(hvp.Entries):
            
            if entry.Type == 4:
                continue
            
            else:
                #get the file path from the repack_info_dict
                file_info = repack_info[str(i)]
                file_crc = file_info[0]
                file_path = file_info[1]
                
                abs_path = os.path.join(unpacked_hvp_folder, file_path)
                
                if abs_path is not None:
                    with open(abs_path, "rb") as f:
                        entry.Data = f.read()
                    
                    entry.UncompressedSize = len(entry.Data)
                    entry.Data = lzokay.compress(entry.Data)
                    
                    entry.CompressedSize = len(entry.Data)
                    
                    entry.DataCRC32 = obscureCRC32(entry.Data)
                    entry.Type = 1
            
            
        if hvp.Endianness == "big":
            br = BinaryReader(endianness=Endian.BIG, encoding="cp932")
        else:
            br = BinaryReader(endianness=Endian.LITTLE, encoding="cp932")
        br.write_struct(hvp)
        
        with open(new_hvp_path, "wb") as f:
            f.write(bytes(br.buffer()))


def unpack_task(hvp_path):
    
    pcounter = perf_counter()
    
    try:
        hvp = read_hvp(hvp_path)
    except Exception as e:
        print(e)
        input(f"Error reading hvp file: {hvp_path}")
        exit(-1)
        
    #create a folder with the name of the hvp file without the file extension
    print(f"Creating folder: {hvp_path[:-4]}")
    hvp_folder = f"{hvp_path[:-4]}"
    os.makedirs(hvp_folder, exist_ok=True)
    
    print("extracting hvp file...")    
    make_dirs(hvp, hvp.Entries[0], hvp_folder)
    
    print("Writing repack_info.json")
    json.dump(repack_info_dict, open(f"{hvp_folder}\\repack_info.json", "w"), indent=4)
    
    input(f"HVP Unpacked in {perf_counter() - pcounter} seconds! Press any key to exit")

def repack_task(hvp_folder):
    hvp_path = f"{hvp_folder}.hvp"
    
    if not os.path.exists(hvp_path):
        input(f"Error! hvp file not found: {hvp_path}")
        exit(-1)
    
    compress = input("Compress files? (y/n): ")
    
    
    pcounter = perf_counter()
    
    try:
        hvp = read_hvp(hvp_path)
    except:
        input(f"Error reading hvp file: {hvp_path}")
        exit(-1)
        
    print("repacking hvp file...")
    
    if compress.lower() == "y":
        repack_compress_hvp(hvp, hvp_folder, hvp_path)
    else:
        repack_hvp(hvp, hvp_folder, hvp_path)
    
    
    input(f"HVP Repacked in {perf_counter() - pcounter} seconds! Press any key to exit")


def tasks():
    task = int(input(f"Enter 1 to unpack or 2 to repack: "))
    
    if task not in [1, 2]:
        input("Invalid task! Press any key to go back")
        tasks()
    
    elif task == 1:
        hvp_path = input("Enter the path to the hvp file: ")
                
        unpack_task(hvp_path)
        
    else:
        hvp_folder = input("Enter the path to the hvp folder: ")
                
        repack_task(hvp_folder)
                


if __name__ == "__main__":
    
    '''pcounter = perf_counter()
    
    profiler = Profile()
    profiler.enable()
    
    main_debug()
    
    profiler.disable()
    profiler.print_stats()
    
    print(f"Total time: {perf_counter() - pcounter}")'''
    if len(sys.argv) < 2:
        tasks()
    else:
        #check if the first argument is a file or a folder
        if os.path.isfile(sys.argv[1]):
            unpack_task(sys.argv[1])
        elif os.path.isdir(sys.argv[1]):
            repack_task(sys.argv[1])
        else:
            input("Unknown argument! Press any key to continue")
            tasks()    
