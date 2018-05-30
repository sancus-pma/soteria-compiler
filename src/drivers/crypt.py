#!/usr/bin/env python

from common import *

import ctypes
import struct
import re

from elftools.elf.elffile import ELFFile
from Crypto.Cipher import AES
from Crypto.Util import Counter

_lib = ctypes.cdll.LoadLibrary(get_data_path() + '/libhmac-spongent.so')

def _print_data(data):
    for i, b in enumerate(data):
        need_nl = True
        print b.encode('hex'),
        if (i + 1) % 26 == 0:
            need_nl = False
            print '\n',
    if need_nl:
        print '\n',

def _gen_lib_call(func):
    def lib_call(key, msg, hex_out=True):
        if args.debug:
            _print_data(msg)
        ret = ctypes.create_string_buffer(16);
        func(key, msg, ctypes.c_ulonglong(len(msg)), ret)
        return ret.raw.encode('hex') if hex_out else ret.raw
    return lib_call

hmac = _gen_lib_call(_lib.hmac)
hkdf = _gen_lib_call(_lib.hkdf)


def _get_spm_section(elf_file, spm):
    spm_section = elf_file.get_section_by_name('.text.spm.' + spm)
    if not spm_section:
        raise ValueError('No such SPM: ' + spm)
    return spm_section


def _parse_hex(hex_str, size=0):
    if size > 0 and len(hex_str) != size:
        raise argparse.ArgumentTypeError('Incorrect hex size')
    try:
        return hex_str.decode('hex')
    except TypeError:
        raise argparse.ArgumentTypeError('Incorrect hex format')


def _parse_key(key_str):
    return _parse_hex(key_str, 32)


def get_spm_key(file, spm, master_key, hex_out=True):
    elf_file = ELFFile(file)
    return hkdf(master_key, _get_spm_section(elf_file, spm).data(), hex_out)


def update_cbc_mac(cipher, y, b):
    ret = ''
    for i in xrange(16):
        ret += chr(ord(y[i]) ^ ord(b[i]))

    return cipher.encrypt(ret)


def ctr_crypt(cipher, ctr, src):
    ret = ''
    b = cipher.encrypt(ctr)

    for i in xrange(16):
        ret += chr(ord(src[i]) ^ ord(b[i]))

    return ret
        

def encrypt_ccm(key, iv, msg):
    cipher = AES.new(key, AES.MODE_ECB)
    ret = ''

    q = 16 - 1 - 13
    y = '\x00' * 16

    # iv_len  = 13
    # tag_len = 16
    # 
    # First block B_0:
    # 0        .. 0        flags
    # 1        .. iv_len   nonce (aka iv)
    # iv_len+1 .. 15       length
    #
    # With flags as (bits):
    # 7        0
    # 6        add present?
    # 5 .. 3   (t - 2) / 2
    # 2 .. 0   q - 1

    b_flags = 0
    b_flags |= ( ( 16 - 2 ) / 2 ) << 3
    b_flags |= q - 1

    b = chr(b_flags) + iv[:13] + chr((len(msg) >> 8) & 0xff) + chr(len(msg) & 0xff)

    y = update_cbc_mac(cipher, y, b)

    # Prepare counter block for encryption:
    # 0        .. 0        flags
    # 1        .. iv_len   nonce (aka iv)
    # iv_len+1 .. 15       counter (initially 1)
    # 
    # With flags as (bits):
    # 7 .. 3   0
    # 2 .. 0   q - 1

    ctr = chr(q - 1) + iv[:13] + '\x00\x01'

    # Authenticate and encrypt the message.
    for i in xrange(0, len(msg), 16):
        y = update_cbc_mac(cipher, y, msg[i:i+16])
        ret += ctr_crypt(cipher, ctr, msg[i:i+16])

        for j in xrange(q):
            incval = (ord(ctr[15-j]) + 1) & 0xff
            ctr = ctr[:15-j] + chr(incval) + ctr[16-j:]
            if incval != 0:
                break

    # Authentication: reset counter and crypt/mask internal tag
    ctr = ctr[:14] + '\x00\x00'

    return ret + ctr_crypt(cipher, ctr, y)


def encrypt_sections(file, loader_key):
    elf_file = ELFFile(file)
    tmp_file = get_tmp('.o')
    shutil.copy(args.in_file, tmp_file)
    stripargs = []

    with open(tmp_file, 'r+') as out_file:
        for section in elf_file.iter_sections():
            match = re.match(r'.text.spm.crypt_(\w+)', section.name)
            if match:
                spm = 'crypt_' + match.group(1)
                spm_padded = spm if len(spm) % 2 == 0 else spm + '\x00'
                spm_key = hmac(loader_key, spm_padded, False)
                spm_iv  = hmac(loader_key, spm_key, False)
                info('CRYPTKEY used for SPM {}: {}'
                     .format(spm, spm_key.encode('hex')))

                out_file.seek(section['sh_offset'])
                section_data = out_file.read(section['sh_size'])

                encrypted_section_data = encrypt_ccm(spm_key, spm_iv, section_data)

                elf = ELFFile(file)
                crypt_section = elf.get_section_by_name('.text.spm.crypt.' + spm)
                if not crypt_section:
                    raise ValueError('No such SPM: ' + spm)
                if not crypt_section['sh_size'] == (section['sh_size'] + 16):
                    raise ValueError('SPM sizes do not match!')

                out_file.seek(crypt_section['sh_offset'])
                out_file.write(encrypted_section_data)

                out_file.seek(section['sh_offset'])
                out_file.write('\x00' * section['sh_size'])

                stripargs += ['--remove-section={}'.format(section.name)]

    stripargs += [tmp_file, args.out_file]
    call_prog('msp430-objcopy', stripargs)


# FIXME this should be moved to the common argument parser!
parser = argparse.ArgumentParser()
parser.add_argument('--verbose',
                    help='Show information messages',
                    action='store_true')
parser.add_argument('--debug',
                    help='Show debug output and keep intermediate files',
                    action='store_true')
parser.add_argument('--loader',
                    help='Specify the loader SPM',
                    metavar='SPM',
                    default='sm_loader')
parser.add_argument('--cryptkey',
                    help='Generate CRYPTKEY for SPM',
                    metavar='SPM')
parser.add_argument('--key',
                    help='128-bit key in hexadecimal format',
                    type=_parse_key,
                    metavar='key',
                    required=True)
parser.add_argument('-o',
                    help='Output file',
                    dest='out_file',
                    metavar='file')
parser.add_argument('in_file',
                    help='Input file',
                    metavar='file',
                    nargs='?')

args = parser.parse_args()
set_args(args)

try:
    with open(args.in_file, 'r') as file:
        loader_key = get_spm_key(file, args.loader, args.key, False)
        if args.cryptkey:
            modname = 'crypt_' + args.cryptkey
            modname = modname if len(modname) % 2 == 0 else modname + '\x00'
            print hmac(loader_key, modname)
        else:
            if not args.out_file:
                fatal_error('Requested to encrypt sections but no ' +
                            'output file given')
            else:
                encrypt_sections(file, loader_key)
except IOError as e:
    fatal_error('Cannot open file: ' + str(e))
except Exception as e:
    fatal_error(str(e))
