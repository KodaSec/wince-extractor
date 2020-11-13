# WinCE Extractor

[![Python version](https://img.shields.io/badge/python-%3E=_3.7-green.svg)](https://www.python.org/downloads/)
[![GitHub license](https://img.shields.io/github/license/KodaSec/wince-extractor.svg)](https://github.com/KodaSec/wince-extractor/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/KodaSec/wince-extractor?style=social)](https://github.com//KodaSec/wince-extractor/stargazers)

### Description

WinCE Extractor is a Python3 program that can extract and decompress execute-in-place (XIP) files from a Windows Compact Embedded ROM image. WinCE Extractor is cross-compatible with Unix and Windows.

### Installation

WinCE Extractor only requires Python3.

```
# Install Python3 and pip3

# Clone the repo
$ git clone https://github.com/KodaSec/wince-extractor.git

# Change the working directory to wince-extractor
$ cd wince-extractor
```

### Usage

```
$ python3 winceextractor.py -h
usage: winceextractor.py [-h] [-d dirpath] [-o offset] image_file

positional arguments:
  image_file  ROM image to extract

optional arguments:
  -h, --help  show this help message and exit
  -d dirpath  save found files/modules to this path
  -o offset   offset of the image file

```

To extract files from a WinCE ROM into a directory:
```
python3 winceextractor.py -d <output_dir> <image_file>
```

### Special Thanks

Willem Hengeveld <<itsme@xs4all.nl>>

Collin Moon <<mooncollin@gmail.com>>

Frank Tursi <<frank@kodasec.com>>
