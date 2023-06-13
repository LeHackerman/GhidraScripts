#!/usr/bin/env python3

import pefile
import json
import os
import argparse


parser = argparse.ArgumentParser(
        prog='SpyEyeAPIHasher',
        description='A small script to hash supplied DLLs API names with SpyEye\'s hashing algorithm.',
        epilog='By: @LeHackerMan')

parser.add_argument('-d',
                    '--directory',
                    dest='dir',
                    default='./',
                    help='The directory containing dll files.')

args = parser.parse_args()

def spyEyeHash(entryName):
    hash = 0
    for char in entryName:
        hash = char ^ (hash << 7 | (hash & 0xffffffff) >> 0x19)
    return hash & 0xffffffff

if __name__ == '__main__':
    apiHashMapping = {}

    for (dirpath, dirnames, filenames) in os.walk(args.dir):
        for file in filenames:
            if(file.endswith(".dll")):

                pe = pefile.PE(os.path.join(dirpath,file))

                for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if entry.name == None:
                        continue

                    entryHash = spyEyeHash(entry.name)
                    apiHashMapping[hex(entryHash)] = entry.name.decode('utf-8')
   
   with open('mapping.json', 'w') as f:
        json.dump(apiHashMapping, f)

