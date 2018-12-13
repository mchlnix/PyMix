import csv
from subprocess import Popen, PIPE, run


PACKET_ID_INDEX = 0
TIMESTAMP_INDEX = 1
SRC_ADDR_INDEX = 2
DEST_ADDR_INDEX = 3
PROTOCOL_INDEX = 4
LENGTH_INDEX = 5


class BackgroundProcess:
    def __init__(self, cmd):
        self.should_run = True

        self.output = ""
        self.process = Popen(cmd, stdout=PIPE)

    def stop(self):
        self.process.terminate()
        self.output = self.process.communicate()[0].decode("ascii")

    def get_output(self):
        return self.output


class ForegroundProcess:
    def __init__(self, cmd):
        self.process = run(cmd)


def get_all_address_ports(csv_file):
    with open(csv_file, "r", newline="") as f:
        log_reader = csv.reader(f, delimiter=",", quotechar="\"")

        src_dict = dict()
        dest_dict = dict()

        src_port = 61000
        dest_port = 62000

        for row in log_reader:
            src_addr = row[SRC_ADDR_INDEX]
            dest_addr = row[DEST_ADDR_INDEX]

            if src_addr not in src_dict:
                while True:
                    port = src_port
                    src_port += 1
                    if port not in src_dict.values():
                        src_dict[src_addr] = port
                        break

            if dest_addr not in dest_dict:
                while True:
                    port = dest_port
                    dest_port += 1
                    if port not in dest_dict.values():
                        dest_dict[dest_addr] = port
                        break

    return src_dict, dest_dict
