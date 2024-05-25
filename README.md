# pokeMONS-EE298
Machine Problem Submissions for EE298

```bash
pip install -r requirements.txt
```

## Machine Problem 1: Hashing v16
Implementing SHA-512 Hashing Algorithm in Python
- accepts both file and string input
```bash
python3 sha512.py "hello world"
```
```bash
python3 sha512.py input.pdf
```

## Machine Problem 2: Port Scanner v16
Implementing an NMAP-like Port Scanner in Python
- uses NMAP-like syntax to accept hostnames, individual and ranges of ip addresses, and even a subnet in CIDR notation
- uses NMAP-like syntax to accept individual and ranges of ports using `-p` tag
- use `-O` tag to enable **OS Detection**
- use `-sU` tag to opt for **UDP Scanning** of port `53` and `161`
- use `-sV` tag to enable **Service Info Detection**
```bash
python3 port_scanner.py scanme.nmap.org -sV -O
```
```bash
python3 port_scanner.py scanme.nmap.org -sU
```
```bash
python3 port_scanner.py 202.92.128.1 -p 22,30-50,80,100-1000
```
```bash
python3 port_scanner.py 202.92.127-128.1-204
```
```bash
python3 port_scanner.py 202.92.1/24
```