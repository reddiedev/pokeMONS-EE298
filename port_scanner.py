import argparse
from simple_chalk import green


def main():
    print(green("MP2: Port Scanner v16"))

    parser = argparse.ArgumentParser(description="NMAP-like Port Scanner")

    parser.add_argument("host", help="Specific host to be scanned")
    parser.add_argument(
        "-O",
        action="store_true",
        required=False,
        help="Implement OS detection",
    )
    parser.add_argument(
        "-sV", action="store_true", help="Implement Service Name/Banner grabbing"
    )
    parser.add_argument("-p", type=str, help="Specify ports to be scanned")

    args = parser.parse_args()
    host = args.host
    option_O = args.O
    option_sV = args.sV
    option_p = args.p

    print(args)


if __name__ == "__main__":
    main()
