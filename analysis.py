import pefile
import sys
import os
import struct
import hashlib
import requests
import json


def directory_handle(data):

    pass


def virustotal_request(hashes):
    API_TOKEN = "446577364d2e8f8a9172bbfb014243b0ba4925bb5a63918da67515913d801f7b"

    headers = {'x-apikey': API_TOKEN}
    # for key in hashes:
    hash_lookup = hashes["md5"]
    build_url = "https://www.virustotal.com/api/v3/files/{}".format(hash_lookup)
        
    api_reponse = requests.get(build_url, headers=headers).json()
    print(api_reponse)

def packed_section_names(section_name):
    packed_section_names_list = {
        "aspack": "Aspack packer",
        "adata": "Aspack packer/Armadillo packer",
        "ASPack": "ASPack Protector",
        "boom": "The Boomerang List Builder (config+exe xored with a single byte key 0x77)",
        "cgg": "CCG Packer (Chinese Packer)",
        "charmve": "Added by the PIN tool",
        "BitArts": "Crunch 2.0 Packer",
        "DAStub": "DAStub Dragon Armor protector",
        "!EPack": "Epack packer",
        "ecode": "Built with EPL",
        "edata": "Built with EPL",
        "enigma1": "Enigma Protector",
        "enigma2": "Enigma Protector",
        "FSG!":  "FSG packer",
        "Gentee": "Gentee installer",
        "kkrunchy": "kkrunchy packer",
        "lz32.dll": "Crinkler",
        "mackt": "ImpRec",
        "MaskPE": "MaskPE Packer",
        "MEW": "MEW packer",
        "mnbvcx1": "Firseria PUP downloaders",
        "mnbvcx2": "Firseria PUP downloaders",
        "MPRESS1": "MPRESS Packer",
        "MPRESS2": "MPRESS Packer",
        "neolite": "Neolite Packer",
        "neolit": "Neolite Packer",
        "nsp0" : "NsPack packer",
        "nsp1": "NsPack packer",
        "nsp2": "NsPack packer",
        "packed": "RLPack packer",
        "PEPACK!!": "Pepack",
        "pebundle": "PEBundle Packer",
        "PEBundle": "PEBundle Packer",
        "PEC2TO": "PECompact packer",
        "PEC2": "PECompact packer",
        "pec1": "PECompact packer",
        "pec2": "PECompact packer",
        "pec3": "PECompact packer",
        "pec4": "PECompact packer",
        "pec5": "PECompact packer",
        "pec6": "PECompact packer",
        "PEC2MO": "PECompact packer",
        "PELOCKnt": "PELock Protector",
        "perplex": "Perplex PE-Protector",
        "PESHiELD": "PEShield Packer",
        "petite" :"Petite Packer",
        "pinclie": "Added by the PIN tool",
        "ProCrypt": "ProCrypt Packer",
        "RLPack": "RLPack Packer",
        "rmnet":"Ramnit virus marker",
        "RCryptor": "RPCrypt Packer",
        "RPCrypt":"RPCrypt Packer",
        "seau":"SeauSFX Packer",
        "sforce3": "StarForce Protection",
        "shrink1" :"Shrinker",
        "shrink2": "Shrinker",
        "shrink3": "Shrinker",
        "spack" : "Simple Pack",
        "svkp" : "SVKP packer",
        "Themida" : "Themida Packer",
        "Themida" : "Themida Packer",
        "taz" : "Some version os PESpin",
        "tsuarch" : "TSULoader",
        "tsustub" : "TSULoader",
        "packed" : "Unknown Packer",
        "PEPACK!!" : "Pepack",
        "Upack" : "Upack packer",
        "ByDwing" : "Upack Packer",
        "UPX0" : "UPX packer",
        "UPX1" : "UPX packer",
        "UPX2" : "UPX packer",
        "UPX3" : "UPX packer",
        "UPX!" : "UPX packer",
        "UPX0" : "UPX Packer",
        "UPX1" : "UPX Packer",
        "UPX2" : "UPX Packer",
        "vmp0" : "VMProtect packer",
        "vmp1" : "VMProtect packer",
        "vmp2" : "VMProtect packer",
        "VProtect" : "Vprotect Packer",
        "winapi" : "Added by API Override tool",
        "WinLicen" : "WinLicense (Themida) Protector",
        "_winzip_" : "WinZip Self-Extractor",
        "WWPACK" : "WWPACK Packer",
        "WWP32" : "WWPACK Packer (WWPack32)",
        "yP" : "Y0da Protector",
        "y0da" : "Y0da Protector"
    }
    print(section_name)
    if packed_section_names_list.get(section_name) is not None:
        print("PACKED")
    

def get_section_data(data):
    pe_handler = pefile.PE(data)
    section_data = pe_handler.sections
    for sections in section_data:
        if sections.Name.decode("utf-8")[0] == '.':
           sections = sections.Name.decode("utf-8")[1:]
        else:
            sections = sections.Name.decode("utf-8")
        
        packed_section_names(sections)
    
    # print(section_data)
def file_handle(data):
    # print("Filename: " + str(data))

    
    pe_handler = pefile.PE(data)
    # print("Import Hash: " + str(pe_handler.get_imphash()))
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    sha256_hasher = hashlib.sha256()

    with open(data, "rb") as NFILE:
        retrieved_data = NFILE.read()
        if not retrieved_data:
            print("Data cannot be read")
            return -1
        md5_hasher.update(retrieved_data)
        sha1_hasher.update(retrieved_data) 
        sha256_hasher.update(retrieved_data)

    print("md5: " + str(md5_hasher.hexdigest()))
    print("sha1: " + str(sha1_hasher.hexdigest()))
    print("sha256: " + str(sha256_hasher.hexdigest()))   
    print("IMP_HASH: " + str(pe_handler.get_imphash()))
    hashes = {
        "md5" : md5_hasher.hexdigest(),
        "sha1": sha1_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
        "IMP_HASH": pe_handler.get_imphash()
    }
        
    # virustotal_request(hashes)

    return 0



def switch_handler(case, data):

    switch = {
        0: directory_handle,
        1: file_handle
    }

    switch.get(case)(data)

def Main():
    
    if len(sys.argv) < 2:
        print("Must use the following format - python3 analysis.py <PE_Executable | Directory >")

        sys.exit(0)

    file_handle(sys.argv[1])

Main()
