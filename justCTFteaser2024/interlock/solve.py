#!/usr/bin/env python

from pwn import *
import json
from time import sleep
import json
import hpke
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import os
from binascii import hexlify, unhexlify

suite = hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305


def send(conn, t, msg):
    conn.sendline(json.dumps({"type": "write", "target": t, "msg": msg}).encode())


def send_alice(conn, msg):
    send(conn, "alice", msg)


def send_bob(conn, msg):
    send(conn, "bob", msg)


def recv(conn, t):
    conn.sendline(json.dumps({"type": "read", "target": t}).encode())
    msg = conn.recvline(keepends=False)
    if msg == b"none":
        return None
    return msg


def recv_blocking(conn, t):
    msg = None
    while msg is None:
        msg = recv(conn, t)
    return msg


def recv_alice(conn):
    return recv_blocking(conn, "alice")


def recv_bob(conn):
    return recv_blocking(conn, "bob")

def fmt(data):
    return hexlify(data).decode()


def ufmt(data):
    return unhexlify(data.encode())

def mitm():
    conn = remote("interlock.nc.jctf.pro", 7331)

    print("Getting the timing")

    conn.recvuntil(b"31 23:")
    minutes = int(conn.recvn(2).decode())
    conn.recvn(1)
    seconds = int(conn.recvn(2).decode())
    conn.recvline()
    delay = 59 - seconds + (59 - minutes)*60
    delay -= 4

    print(f"Sleeping for {delay} s")
    sleep(delay)

    print("Generating ou keys for spoofing")
    # alice' spoofed key
    skap = suite.KEM.generate_private_key()
    pkap = skap.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )

    # bob' spoofed key
    skbp = suite.KEM.generate_private_key()
    pkbp = skbp.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )

    print("Starting bob and alice")
    send_bob(conn, "start")
    send_alice(conn, "start")

    print("receiving alice mess and signature")
    c1 = recv_alice(conn).decode()
    m1_sig = json.loads(recv_alice(conn).decode())

    m1_str = m1_sig["m1"]
    m1 = json.loads(m1_str)

    x1 = unhexlify(m1["x1"])
    n1 = unhexlify(m1["n1"])

    pka = unhexlify(m1["pka"])

    print("m1 :", m1)
    print("spoof and send our sign to bob c1")
    
    ### spoof send to bob c1
    m1p = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pkap)})
    c1_dp = hashes.Hash(hashes.SHA3_256())
    c1_dp.update(m1p.encode())
    c1p = c1_dp.finalize()
    send_bob(conn, fmt(c1p))

    print("spoof and send our sign to bob m1_sig")
    ### spoof send to bob m1_sig
    s1p = skap.sign(m1p.encode(), ec.ECDSA(hashes.SHA3_256()))
    m1_sigp = json.dumps({"m1": m1p, "s1": fmt(s1p)})
    send_bob(conn, m1_sigp)

    m2_enc = json.loads(recv_bob(conn).decode())

    print("decrypting bob ...")
    ## decrypt bob
    encap, ct, pkb = ufmt(m2_enc["encap"]), ufmt(m2_enc["ct"]), ufmt(m2_enc["pkb"])
    pkb_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pkb)
    m2 = suite.open_auth(
        encap,
        skap,
        pkb_k,
        info=b"interlock",
        aad=pkb,
        ciphertext=ct,
    )

    m2 = json.loads(m2)
    x2 = unhexlify(m2["x2"])
    print("bob decrypted :", m2)

    ### spoof bob send
    print("spoofing end for correlation")
    m2 = json.dumps(
        {"x2": m2["x2"], "pka": fmt(pka), "m1": m1_str, "n2": m2["n2"]}
    )

    pka_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pka)
    encap, ct = suite.seal_auth(
        pka_k, skbp, info=b"interlock", aad=pkbp, message=m2.encode()
    )
    m2_encp = json.dumps({"encap": fmt(encap), "ct": fmt(ct), "pkb": fmt(pkbp)})

    send_alice(conn, m2_encp)

    conn.sendline(json.dumps({"type": "quit"}).encode())

    rec1 = conn.recvline().strip()
    print(rec1)
    if rec1 == b"Error":
        print(conn.recvline().strip())
        return
    print(conn.recvuntil(b"Give me x1: "))
    conn.sendline(hexlify(x1))

    print(conn.recvuntil(b"Give me x2: "))
    conn.sendline(hexlify(x2))

    print(conn.recvline())

if __name__ == "__main__":
    mitm()
