#!/usr/bin/python3
from random import randint, choice
from Receiver import get_udp
from util import i2b, ip2i

requests = ["Hello"]*10

dest_ports = [60001, 60002, 60003, 60004, 60005]

entry_addr = ("127.0.0.1", 20000)

def header(ip, port):
    return i2b(ip2i(ip), 4) + i2b(port,2)

if __name__ == "__main__":
    # get a receiver with a random port in the 5xxxx
    ip = "127.0.0.1"
    port = randint(50000, 59999)

    with get_udp((ip, port)) as r:
        # send requests to predetermined destinations
        for payload in requests:
            dest_port = choice(dest_ports)

            print("Sending to", dest_port)
            r.sendto(header(ip, dest_port) + payload.encode("utf-8"),
                     entry_addr)

# wait for responses and check with what we expected
        while True:
            data = r.recv()

            print(r.getaddr(), data)

    

