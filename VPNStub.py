import select
from socket import socket, AF_INET, SOCK_STREAM

IP = "127.0.0.1"
PORT = 60050
OPEN_CONNECTIONS = 10

to_mix = socket(AF_INET, SOCK_STREAM)
to_mix.bind((IP, PORT))
to_mix.listen(OPEN_CONNECTIONS)

print(f"Listening on {IP}:{PORT}")

read_list = [to_mix]


if __name__ == "__main__":
    while True:
        readable, _, _ = select.select(read_list, [], [])

        for s in readable:
            if s is to_mix:
                client_socket, address = to_mix.accept()
                read_list.append(client_socket)
                print(f"Connection from {address}")
            else:
                length = s.recv(2)

                if length:
                    len_int = length[1]
                    len_int += length[0] << 8
                    data = s.recv(len_int)

                    chan_id = data[1]
                    chan_id += data[0] << 8

                    print(f"Got message from {chan_id}")
                else:
                    s.close()
                    read_list.remove(s)
                    continue
