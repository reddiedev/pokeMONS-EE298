import argparse
import os
import time

from sota_sha512 import SOTA_Hasher
from sha512 import Hasher
from simple_chalk import green, magenta, yellow, red


def main():
    print(green("MP1: Hashing Speed Benchmarks"))
    parser = argparse.ArgumentParser(description="Accepts file or string input")
    parser.add_argument("input", help="Input can be either a file path or a string.")

    args = parser.parse_args()
    input_arg = args.input

    input_data = ""
    sota_hasher = SOTA_Hasher()
    own_hasher = Hasher()

    current_path = os.getcwd()
    file_path = os.path.join(current_path, input_arg)

    if os.path.isfile(file_path):
        with open(file_path, "rb") as file:
            input_data = file.read()

    else:
        input_data = str(input_arg).encode("utf-8")
        print(yellow("Input: ") + str(input_arg))
        print()

    print()
    print(magenta("SOTA IMPLEMENTATION"))
    sota_start = time.time()
    sota_hash = sota_hasher.sha512(input_data)
    sota_end = time.time()
    sota_time = sota_end - sota_start

    print(magenta("Hash: ") + sota_hash)
    print(magenta("Time: ") + str(sota_time) + " seconds")

    print()
    print(magenta("OWN IMPLEMENTATION"))
    own_start = time.time()
    own_hash = own_hasher.sha512(input_data)
    own_end = time.time()
    own_time = own_end - own_start
    print(magenta("Hash: ") + own_hash)
    print(magenta("Time: ") + str(own_time) + " seconds")


    percent_increase = ((own_time - sota_time) / sota_time) * 100

    print()
    print(magenta("RESULTS"))
    if own_hash == sota_hash:
        print(green("Hashes are a match!"))
        print("Own Implementation was " + str(round(percent_increase,2)) + "% longer than SOTA")
    else:
        print(red("Hashes are not a match!"))

    return hash


if __name__ == "__main__":
    main()
