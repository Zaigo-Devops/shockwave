from django.core.management.base import BaseCommand

from ecdsa import SigningKey, NIST256p
import hashlib
import hmac
import binascii


class Command(BaseCommand):
    help = 'Unlock the device with the code'

    def handle(self, *args, **options):
        sk = SigningKey.generate(curve=NIST256p)
        sk.from_pem("""
         -----BEGIN EC PRIVATE KEY-----
         MHcCAQEEIMaGe/ECPfwLyz1XAodBt3Y9VIAYA+R5zr8anbb79GqBoAoGCCqGSM49
         AwEHoUQDQgAECwqZsBUJpT1Yua2PKB9+djq+l6iQbiVbnfCPMaEUyyv5GHt3srFp
         HKhFVov1O8k6mw+2rMdybjfwtBx8NXZbIg==
         -----END EC PRIVATE KEY-----
        """)
        hex_string = "0100D1118F928F77C9F2"
        if len(hex_string) == 20:
            msg = bytearray.fromhex(hex_string)
            sig = sk.sign(msg, hashfunc=hashlib.sha256)
            print("To Hex String msg", binascii.hexlify(msg))
            sbintr = binascii.hexlify(sig)
            print("To Hex String Sig", sbintr.upper())
            print("To Hex String Sig", sbintr)
