#!/usr/bin/python3

from time import sleep

from tests.Test_Helpers import BackgroundProcess, ForegroundProcess, get_all_address_ports

log_file = "tests/data/Left4Dead2_in.csv"

src_ports, dest_ports = get_all_address_ports(log_file)

listener_command = ["tests/Packet_Listener.py", "tests/tmp/recv-log"]

listener_command.extend(str(port) for port in dest_ports.values())

print("Starting Listener")

listener = BackgroundProcess(listener_command)

sender_command = ["tests/Replay_Log.py", log_file]

print("Starting Sender")

ForegroundProcess(sender_command)

sleep(2)

listener.stop()

print(listener.get_output())

ForegroundProcess(["tests/measure_delay.py"])
