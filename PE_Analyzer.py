#!/usr/bin/python
import sys
import os
import socket
import time
import hashlib
import re
import string
import struct
try:
  import pefile
  import ssdeep
  import magic
  import pyimpfuzzy
  import yara
except ImportError:
  print '''
The following non-standard packages are required:

pefile
ssdeep
magic
pyimpfuzzy
yara

These are generall availble via pip:
sudo pip install <foo>
        '''

def Main(exe):
  ape = False
  try:
    ape = pefile.PE(exe, fast_load = True)
  except:
    pass
  if ape != False:
    '''
    After successful verification that the sample is a valid PE,
    generate some static meta about the header characteristics.
    '''
    pe          = pefile.PE(exe)
    sample      = ReadSample(exe)
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

    '''
    Look for Crpyto Constants with YARA
    '''
    print '#  Scanning with YARA signatures'
    ScanWithYARA(sample)
    '''
    The following functions look for cleartext and XOR encoded strings
    of interest [domains, IP's, email addresses, pdb paths, executables]
    and print them in seperate sections.  The last function will attempt
    to carve out any single byte XOR encoded execcutables and give them 
    the correct extension.
    '''
    regex = ['[a-zA-Z0-9-\s\\\.\:]+\.pdb', \
             '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', \
             '[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})', \
             '[A-z|a-z|0-9]{1,}\.(dll|scr|exe|bat)']

    print '# Cleartext Interesting Strings'
    FindStrings(sample, regex)

    print '# XOR Encdoded Interesting Strings'
    FindXorStrings(sample, regex)

    print '# Possible Domain Names'
    DomainHunter(sample)

    print '# Carving Additional PEs'
    MultiByteXor(sample)
  else:
    print 'This application only supports analyzing Windows PEs'

def ScanWithYARA(sample):
  '''
  By default this package includes crpyto constant signatures.
  The user is also encouraged to drop their own YARA signatures
  into the same directory as the script with a .yar extension,
  these will also be read and applied to the sample analysis.
  '''
  
  directory = os.path.dirname(os.path.abspath(__file__))
  if os.name == 'nt':
    path = directory + '\\'
  elif os.name == 'posix':
    path = directory + '/'
  for sig in os.listdir(path):
    if sig.endswith('.yar'):
      print '  Loaded ruleset: ' + str(sig)
      f       = open(path + sig, 'rb')
      text    = f.read()
      f.close()
      rules   = yara.compile(source=text)
      matches = rules.match(data=sample)
      for match in matches:
        print '  Sample matched YARA rule: ' + str(match)

def MultiByteXor(sample):
  '''
  Find most commmon 4 byte sequence and ROR through it
  looking for MZ headers and valid PE's.  The sequence
  is also rotated right [ ROR ] with the lambda, below.
  Find the current directory and OS version so we can create
  the appropriate path for our temp file that will contain
  carved PEs
  '''
  directory = os.path.dirname(os.path.abspath(__file__))
  if os.name == 'nt':
    path = directory + '\\'
  elif os.name == 'posix':
    path = directory + '/'
  mz        = re.compile('\\x4D\\x5A\\x90')
  mz_len    = len(sample)
  buf       = 4096
  iters     = int(mz_len/buf)
  key_chain = []
  for i in range(0, iters):
    keys    = {}
    segment = sample[i*buf:i*buf+buf] 
    for a in range(0, len(segment), 4):
      chunk = struct.unpack('>I', segment[a:a+4])
      if chunk[0] not in keys:
        keys[chunk[0]] = 1
      else:
        keys[chunk[0]] = keys[chunk[0]] + 1

    max_val = 0
    pos_key = 0
    for key, value in keys.iteritems():
      if value > max_val:
        max_val = value
        pos_key = key
    ror = lambda val, r_bits, max_bits: \
          ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
          (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

    '''
    Loop over the rotate bits in increments of 8.
    The key_chain makes sure we don't try the same
    XOR key permutation more than once to save some
    CPU cycles.
    '''
    for k in range(0, 32, 8):
      xor_key = ror(pos_key, k, 32)
      if xor_key in key_chain:
        continue
      else:
        key_chain.append(xor_key)
      decoded = ''
      for i in range(0, len(sample), 4):
        chunk    = struct.unpack('>I', sample[i:i+4])
        cleart   = chunk[0] ^ xor_key
        decoded  += struct.pack('>I', cleart)

      '''
      MZ header is searched for throughout the binary.
      The binary object is then sliced and written to disk to test
      with the pefile library for a valid PE.  If that's found, the PE
      is trimmed of overlay data so hashes can be queried for.
      '''

      for mz_offset in re.finditer(mz, decoded):
        if mz_offset.start() > 0:
          blob = decoded[mz_offset.start():mz_len]
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
          '''
          Only write and alert if file doesn't exist.
          '''
          if not os.path.isfile(path + checksum + ext):
            f = open(path + checksum + ext, 'wb')
            f.write(new_mz)
            print '  Found embedded PE at offset ' + hex(mz_offset.start()) + ' with XOR key [' + hex(xor_key) + '] and MD5 of ' + str(checksum)

def GetExt(pe):
  '''
  Query for and return extension type for quick identification.
  '''
  if pe.is_dll() == True:
    return '.dll_'
  if pe.is_driver() == True:
    return '.sys_'
  if pe.is_exe() == True:
    return '.exe_'
  else:
    return '.bin_'
  
def DomainHunter(sample):
  ''' 
  More complicated Regexes with capture groups and better logic were attempted.
  This started to exhibit O(N^2) behavior and was simplified.  The Regex below
  excludes 2 periods together in the initial string [ .. ] then looks for a 
  valid starting character for the domain and is anchored by a TLD.
  '''
  regex = re.compile('(?!\.\.)([a-zA-Z0-9_][a-zA-Z0-9\.\-\_]{6,255})\.(com|net|org|co|biz|info|me|us|uk|ca|de|jp|au|fr|ru|ch|it|nl|se|no|es|su|mobi)')
  for key in range(0,0x100):
    if key == 0x20:
      continue
    binary  = xor(sample, key)
    for match in re.finditer(regex, binary):
      s = match.start()
      e = match.end()
      print '  Domain found at offset ' + hex(s) + ' with XOR key [' + hex(key) + ']: ' + str(binary[s:e])

def FindStrings(sample, regex):
  '''
  Pretty straight forward Regex for interesting strings.
  '''
  for entry in regex:
    for match in re.finditer(entry, sample):
      s = match.start()
      e = match.end()
      print '  Found at offset ' + hex(s) + ' --> ' + sample[s:e]

def FindXorStrings(sample, regex):
  '''
  The same as FindStrings except we rotate from 0x01 - 0xFF XOR keys
  before doing our Regex search.
  '''
  for key in range(1,0x100):
    if key == 0x20:
      continue
    binary = xor(sample, key)

    for entry in regex:
      for match in re.finditer(entry, binary):
        s = match.start()
        e = match.end()
        print '  String found at offset ' + hex(s) + ' with XOR Key [' + hex(key) + '] --> ' + binary[s:e]

def xor(data, key):
  '''
  XOR the sample and return.
  '''
  decode = ''
  for d in data:
    decode = decode + chr(ord(d) ^ key)
  return decode

def ReadSample(exe):
  '''
  Read sample into an object.
  '''
  f = open(exe,'rb+')
  binary = f.read()
  f.close()
  return binary

if __name__ == "__main__":
  if len(sys.argv) == 2:
    if sys.argv[1] == '-h':
      print '''
###### PE Analyzer ######
This script will extract static details from a valid PE
and print them out.  Items analyzed:
-Hashes
-Import, Exports and Import hash
-Static details such as compile time and version information
-Custom YARA signatures as well as included crypto constant sigs
-Fuzzy Hashes for PE, Imports and Sections
-Cleartext and XOR encoded strings of interest
-Cleartext and XOR encoded PE's embedded within sample 

Requires path to a file to be analyzed like:
  PE_Analyzer.py foo.exe
            '''
    else:
      Main(sys.argv[1])
  else:
    print "Requires path to a file to be analyzed like:\nPE_Analyzer.py foo.exe\nRun with -h for description"

