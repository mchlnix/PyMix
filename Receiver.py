from socket import socket, AF_INET, SOCK_DGRAM as UDP, SOCK_STREAM as TCP

BUFFER_SIZE = 1024

def get_tcp(ip_port):
    return Receiver(TCP, ip_port)

def get_udp(ip_port):
    return Receiver(UDP, ip_port)

class Receiver():
    def __init__(self, sock_type, ip_port):
        self.type = sock_type
        self.addr = ip_port
        self.sock = None
        self.conn = None
        self.ret_addr = None

        self._setup()

    def _setup(self):
        self.__exit__(None, None, None)

        self.sock = socket(AF_INET, self.type)
        self.sock.bind(self.addr)

    def reset(self):
        self._setup()
        self.__enter__()

    def open(self):
        if self.type == TCP:
            self.sock.listen(1)
            self.conn, self.ret_addr = self.sock.accept()

    def close(self):
        if self.type == TCP:
            self.sock.close()

    def recv(self, buffersize=BUFFER_SIZE):
        if self.type == TCP:
            data = self.conn.recv(buffersize)
        elif self.type == UDP:
            data, self.ret_addr = self.sock.recvfrom(buffersize)

        return data

    def sendto(self, packet, dest):
        return self.sock.sendto(packet, dest)

    def getaddr(self):
        if self.type == TCP:
            return self.ret_addr
        elif self.type == UDP:
            return self.ret_addr

        return None

    def getsock(self):
        return self.sock

    def setsock(self, sock):
        self.type = TCP
        self.addr = sock.getsockname()

        try:
            self.sock.close()
        except IOError:
            pass

        self.sock = sock
        self.conn = sock

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
