#!/usr/bin/python
import sys
import os
import pefile
import hashlib
import re
import ssdeep
import string
import magic
import pyimpfuzzy
import socket
import time

def Main(exe):
  ape = False
  try:
    ape = pefile.PE(exe, fast_load = True)
  except:
    pass
  if ape != False:
    pe          = pefile.PE(exe)
    sample      = ReadSample(exe)
    sample_type = 'exe'
    print '# MD5              : ' + str(hashlib.md5(sample).hexdigest())
    print '# SHA1             : ' + str(hashlib.sha1(sample).hexdigest())
    print '# SHA256           : ' + str(hashlib.sha256(sample).hexdigest())
    print '# SSDEEP           : ' + str(ssdeep.hash(sample))
    print '# Import Hash      : ' + str(pe.get_imphash())
    print '# Fuzzy Import Hash: ' + str(pyimpfuzzy.get_impfuzzy(exe))
    print '# File Size        : ' + str(len(sample))
    print '# Major Version    : ' + str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    print '# Minor Version    : ' + str(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    print '# Compile time     : ' + str(time.strftime('%m/%d/%Y %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp)))
    mime_magic                   = magic.Magic(mime=True)
    print '# MIME Type        : ' + str(mime_magic.from_buffer(sample))
    full_magic                   = magic.Magic()
    print '# File Magic       : ' + str(full_magic.from_buffer(sample))

    print '# PE Sections      : '
    for section in pe.sections:
      print '  Name  : ' + str(section.Name)
      print '  MD5   : ' + str(section.get_hash_md5())
      print '  Size  : ' + str(section.SizeOfRawData)
      start     = section.PointerToRawData
      endofdata = start + section.SizeOfRawData
      print '  SSDEEP: ' + str(ssdeep.hash(section.get_data(start)[:endofdata]))
      print ''
    print '# Imports:'
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
      for imp in entry.imports:
        print '  ' + str(entry.dll) + '!' + str(imp.name)

    print '# Exports:'
    try:
      for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print '  ' + str(exp.name)
    except:
      print '  <none>'
      pass
    regex = ['[a-zA-Z0-9-\s\\\.\:]+\.pdb', \
             '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', \
             '[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})', \
             '[A-z|a-z|0-9]{1,}\.(dll|scr|exe|bat)']

    print '# Cleartext Interesting Strings'
    FindStrings(sample, regex)

    print '# XOR Encdoded Interesting Strings'
    for key in range(1,0x100):
      if key == 0x20:
        continue
      binary = xor(sample, key)
      FindXorStrings(binary, key, regex)

    print '# Possible Domain Names'
    DomainHunter(sample)

    print '# Carving Additional PEs'
    CarveEXE(sample)

  else:
    print 'This application only supports analyzing Windows PEs'

def CarveEXE(sample):
  directory = os.path.dirname(os.path.abspath(__file__))
  if os.name == 'nt':
    path = directory + '\\'
  elif os.name == 'posix':
    path = directory + '/'
  mz     = re.compile('\\x4D\\x5A\\x90')
  mz_len = len(sample)
  for key in range(0,0x100):
    binary = xor(sample, key)
    for mz_offset in re.finditer(mz, binary):
      if mz_offset.start() > 0:
        blob = binary[mz_offset.start():mz_len]
        try:
          f      = open(path + 'blob.tmp', 'wb')
          f.write(blob)
          f.close()
          pe     = pefile.PE(path + 'blob.tmp')
          offset = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
          new_mz = blob[:offset]
          os.remove(path + 'blob.tmp')
        except:
          os.remove(path + 'blob.tmp')
          continue
        ext      = GetExt(pe)
        checksum = hashlib.md5(new_mz).hexdigest()
        f        = open(path + checksum + ext, 'wb')
        f.write(new_mz)
        print '  Found embedded PE at offset ' + str(mz_offset.start()) + ' with XOR key [' + hex(key) + '] and MD5 of ' + str(checksum)

def GetExt(pe):
  if pe.is_dll() == True:
    return '.dll_'
  if pe.is_driver() == True:
    return '.sys_'
  if pe.is_exe() == True:
    return '.exe_'
  else:
    return '.bin_'
  
def DomainHunter(sample):
  regex = re.compile('(?!\.\.)([a-zA-Z0-9][a-zA-Z0-9.-]{6,255})\.(com|net|org|co|biz|info|me|us|uk|ca|de|jp|au|fr|ru|ch|it|nl|se|no|es|su|mobi)')
  for key in range(0,0x100):
    if key == 0x20:
      continue
    binary  = xor(sample, key)
    for match in re.finditer(regex, binary):
      s = match.start()
      e = match.end()
      print '  Domain found at offset ' + hex(s) + ' with XOR key [' + hex(key) + ']: ' + str(binary[s:e])

def FindStrings(binary, regex):
  for entry in regex:
    for match in re.finditer(entry, binary):
      s = match.start()
      e = match.end()
      print '  Found at offset ' + hex(s) + ' --> ' + binary[s:e]

def FindXorStrings(binary, key, regex):
  for entry in regex:
    for match in re.finditer(entry, binary):
      s = match.start()
      e = match.end()
      print '  XOR Key [' + hex(key) + '] found at offset ' + hex(s) + ' --> ' + binary[s:e]

def xor(data, key):
  decode = ''
  for d in data:
    decode = decode + chr(ord(d) ^ key)
  return decode

def ReadSample(exe):
  f = open(exe,'rb+')
  binary = f.read()
  f.close()
  return binary

if __name__ == "__main__":
  if len(sys.argv) == 2:
    Main(sys.argv[1])
  else:
    print "Requires path to a file to be analyzed like\nPE_Analyzer.py foo.exe"

