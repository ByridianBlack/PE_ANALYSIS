#!/usr/bin/python3
import pefile
import hashlib
import sys


if len(sys.argv) < 2:
    print("Enter in a file name")
    sys.exit(0)

filename = sys.argv[1]

executable = pefile.PE(filename)

imphash = executable.get_imphash()

md5_hash = hashlib.md5()
sha1_hash = hashlib.sha1()
sha256_hash = hashlib.sha256()

BUFFER_SIZE = 65536

with open(filename, 'rb') as NFILE:
    data_read = NFILE.read(BUFFER_SIZE)
    while len(data_read) > 0:
        md5_hash.update(data_read)
        sha1_hash.update(data_read)
        sha256_hash.update(data_read)
        data_read = NFILE.read(BUFFER_SIZE)

print("ND5: " + str(md5_hash.hexdigest()))
print("SHA1: " + str(sha1_hash.hexdigest()))
print("SHA256: " + str(sha256_hash.hexdigest()))


print("IMPHASH: " + str(imphash))
