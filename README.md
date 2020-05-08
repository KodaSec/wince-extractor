# WinCE Extractor

[![Python version](https://www.python.org/downloads/)](https://img.shields.io/badge/python-%3E=_3.7-green.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/KodaSec/wince-extractor/graphs/commit-activity)
[![GitHub license](https://img.shields.io/github/license/KodaSec/wince-extractor.svg)](https://github.com/KodaSec/wince-extractor/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/badges/shields.svg?style=social&label=Stars)](https://github.com//KodaSec/wince-extractor/stargazers)

### Installation

Program requires Windows 32-bit Python due to DLL dependency.

```
# Clone the repo
> git clone https://github.com/KodaSec/wince-extractor.git

# Change the working directory to wince-extractor
> cd wince-extractor

# Install 32bit Python3 and pip3 if they are not installed

# Install dependency
> pip3 install sortedcontainers

# Download CECompress.dll
> (new-object System.Net.WebClient).DownloadFile('http://nah6.com/~itsme/cvs-xdadevtools/dumprom/CECompress.dll','C:\CECompress.dll')
```

### Usage

```
$ python3 wince-extractor.py --help
usage: wince-extractor.py [-h] [-d dirpath] [-v] [-q] [-n]
                          [-u <ofs>L<len>:desc] [-x <offset>] [-i <offset>]
                          [-3] [-4] [-5]
                          imagefile [offset] [imagefile [offset] ...]

positional arguments:
  imagefile [offset]

optional arguments:
  -h, --help           show this help message and exit
  -d dirpath           save found files/modules to this path
  -v                   verbose : print alignment, struct contents
  -q                   quiet : don't print anything
  -n                   don't use negative rva fix
  -u <ofs>L<len>:desc  add user defined memory regions to complete image
  -x <offset>          process XIP chain at offset
  -i <offset>          specifiy image start offset
  -3                   use wince3.x decompression
  -4                   use wince4.x decompression [ default ]
  -5                   use wince4.x decompress, and e32rom for wm2005
```

To extract from a WinCE ROM:
```
python3 wince-extractor.py -d <output_dir> <input_file>
```

### Special Thanks

Willem Hengeveld <itsme@xs4all.nl>
Collin Moon <mooncollin@gmail.com>
Frank Tursi <frank@kodasec.com>
