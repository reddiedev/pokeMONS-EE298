import argparse
from simple_chalk import green
import ipaddress


class PortScanner:
    def __init__(self) -> None:
        self.addresses: list[str] = []
        pass

    def generateHosts(self, input: str):
        addresses = []
        for item in input.split(","):
            if "-" in item:  # ip range
                start, end = item.split("-")
                start_ip = ipaddress.ip_address(start)
                if "." in end:  # 202.92.128.1-202.92.128.254
                    end_ip = ipaddress.ip_address(end)
                else:  # 202.92.128.1-254
                    octets = [start.split(".")[:-1]][0]
                    octets.append(end)
                    end_ip = ipaddress.ip_address(".".join(octets))
                print(start_ip, end_ip)
                addresses.extend(str(ip) for ip in range(start_ip, end_ip + 1))

            elif "/" in item:  # cidr network
                network = ipaddress.ip_network(item, strict=False)
                addresses.extend(str(ip) for ip in network.hosts())

            else:  # ip address or hostname
                addresses.append(item)

        self.addresses = addresses
        return


def main():
    print(green("MP2: Port Scanner v16"))

    parser = argparse.ArgumentParser(description="NMAP-like Port Scanner")

    parser.add_argument("input_hosts", help="Specific host to be scanned")
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
    option_O = args.O
    option_sV = args.sV
    option_p = args.p

    print(args)

    scanner = PortScanner()
    scanner.generateHosts(args.input_hosts)
    print(scanner.addresses)


if __name__ == "__main__":
    main()
