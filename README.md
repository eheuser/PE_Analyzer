###### PE Analyzer ######
This script will extract static details from a valid PE
and print them out.  Items analyzed:
-Hashes
-Import, Exports and Import hash
-Static details such sa compile time and version information
-Fuzzy Hashes for PE, Imports and Sections
-Cleartext and XOR encoded strings of interest
-Cleartext and XOR encoded PE's embedded within sample

Requires path to a file to be analyzed like:
  PE_Analyzer.py foo.exe

