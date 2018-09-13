#!/usr/bin/python3
from argparse import ArgumentParser as AP
from Receiver import get_udp

parser = AP(description="Receives data on the specified ip:port using UDP and prints it on stdout.")
parser.add_argument("ip:port", help="IP and Port pair to listen for datagrams on")
parser.add_argument("-t", "--tcp", help="Use TCP instead of UDP to listen for data", action="store_true")

BUFFER_SIZE = 65535

if __name__ == "__main__":
    args = parser.parse_args()
    
    print("Use Ctrl+C to quit.")

    ip, port = getattr(args, "ip:port").split(":")
    port = int(port)
    print("Listening on {}:{}".format(ip, port))

    with get_udp((ip, port)) as r:
        while True:
            try:
                data = r.recv(BUFFER_SIZE)

                if data == b'':
                    break

                print(r.getaddr(), len(data), data.decode("utf-8"))
                r.sendto(bytes("Got Message. Thanks.", "utf-8"), r.getaddr())
                
            except KeyboardInterrupt as kbi:
                print("Received Ctrl+C, quitting.")
                break


            
