import sys, os
from cx_Freeze import setup, Executable

files = ["hashes.json",
         "Add HVFilePacker to right click menu.bat",
         "Remove HVFilePacker from right click menu.bat",]

target = Executable(
    script="HVFilePacker.py",
)


setup(
    name = "HVFilePacker",
    version = "1.0",
    description = "HVP File Unpacker/Repacker",
    author = "Al-Hydra",
    options = {"build_exe" : {"include_files" : files}},
    executables = [target]
)