"""Machine Problem 1: SHA512 Hashing Algorithm"""

__authors__ = "Sean Red Mendoza, Lance Atienza"
__team_name__ = "pokeMONS"
__subject__ = "CoE 197 KA-FOPQ: Computer and Network Security"
__ay_sem__ = "AY 2023-2024 2nd Semester"


import argparse
import os
import time
from simple_chalk import green, magenta, yellow, red

### Main reference: https://en.wikipedia.org/wiki/SHA-2#Pseudocode


class Hasher:
    def __init__(self) -> None:
        # Initial hash values
        self.hash_init = [
            0x6A09E667F3BCC908,
            0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1,
            0x510E527FADE682D1,
            0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B,
            0x5BE0CD19137E2179,
        ]

        # Constants
        self.constants = [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]

    def right_rotate(self, val, bits):
        return ((val >> bits) | (val << (64 - bits))) & 0xFFFFFFFFFFFFFFFF

    def sha512(self, orig_message_bytes):
        # Convert orig_message to bytes
        orig_message_len = len(orig_message_bytes) * 8

        # Append a single '1' bit to orig_message
        orig_message_bytes += b"\x80"

        # append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 128) is a multiple of 1024
        padding_len = (
            (1024 - (orig_message_len + 1 + 128) % 1024)
        ) // 8  # Convert to bits
        orig_message_bytes += b"\x00" * padding_len

        # append L as a 128-bit big-endian integer
        orig_message_bytes += orig_message_len.to_bytes(16, "big")

        # split into 1024 bit chunks
        chunks = []
        for i in range(len(orig_message_bytes) // 128):
            chunks.append(orig_message_bytes[i * 128 : (i + 1) * 128])

        # Break into 1024-bit chunks
        for chunk_element in chunks:

            array = []
            for i in range(0, 128, 8):
                array.append(int.from_bytes(chunk_element[i : i + 8], "big"))

            # Extend the first 16 64-bit words into the remaining 80 64-bit words
            for i in range(16, 80):
                s0 = (
                    self.right_rotate(array[i - 15], 1)
                    ^ self.right_rotate(array[i - 15], 8)
                    ^ (array[i - 15] >> 7)
                )
                s1 = (
                    self.right_rotate(array[i - 2], 19)
                    ^ self.right_rotate(array[i - 2], 61)
                    ^ (array[i - 2] >> 6)
                )
                array.append(
                    (array[i - 16] + s0 + array[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF
                )

            # Initialize working variables to current hash value:
            hash_init = self.hash_init
            a, b, c, d, e, f, g, h = hash_init

            # Compression function main loop
            for i in range(80):
                S1 = (
                    self.right_rotate(e, 14)
                    ^ self.right_rotate(e, 18)
                    ^ self.right_rotate(e, 41)
                )
                ch = (e & f) ^ ((~e) & g)
                temp1 = (
                    h + S1 + ch + self.constants[i] + array[i]
                ) & 0xFFFFFFFFFFFFFFFF
                S0 = (
                    self.right_rotate(a, 28)
                    ^ self.right_rotate(a, 34)
                    ^ self.right_rotate(a, 39)
                )
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

            # Add the compressed chunk to the current hash value:
            hash_init[0] = (hash_init[0] + a) & 0xFFFFFFFFFFFFFFFF
            hash_init[1] = (hash_init[1] + b) & 0xFFFFFFFFFFFFFFFF
            hash_init[2] = (hash_init[2] + c) & 0xFFFFFFFFFFFFFFFF
            hash_init[3] = (hash_init[3] + d) & 0xFFFFFFFFFFFFFFFF
            hash_init[4] = (hash_init[4] + e) & 0xFFFFFFFFFFFFFFFF
            hash_init[5] = (hash_init[5] + f) & 0xFFFFFFFFFFFFFFFF
            hash_init[6] = (hash_init[6] + g) & 0xFFFFFFFFFFFFFFFF
            hash_init[7] = (hash_init[7] + h) & 0xFFFFFFFFFFFFFFFF

        # Produce the final hashed message. Concactenate the hex of each hash value
        hashed_values = []
        for element in hash_init:
            hashed_values.append(hex(element)[2:])

        hashed_message = "".join(hashed_values)

        return hashed_message


def main():
    print(green("MP1: Hashing Speed Benchmarks"))
    parser = argparse.ArgumentParser(description="Accepts file or string input")
    parser.add_argument("input", help="Input can be either a file path or a string.")

    args = parser.parse_args()
    input_arg = args.input

    input_data = ""
    hasher = Hasher()

    current_path = os.getcwd()
    file_path = os.path.join(current_path,input_arg)

    if os.path.isfile(file_path):
        with open(file_path, "rb") as file:
            input_data = file.read()

    else:
        input_data = str(input_arg).encode("utf-8")
        print(yellow("Input: ") + str(input_data))
        print()

    own_start = time.time()
    own_hash = hasher.sha512(input_data)
    own_end = time.time()
    own_time = own_end - own_start

    print(magenta("Hash: ") + own_hash)
    print(magenta("Time: ") + str(own_time) + " seconds")

    return hash


if __name__ == "__main__":
    main()
