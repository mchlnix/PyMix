#!/usr/bin/python3
from collections import Counter
from math import ceil

delays = {}

with open("tests/tmp/recv-log") as f:
    recv_packets = {int(line.split()[0]): float(line.split()[1]) for line in
                    f.readlines()}

with open("tests/tmp/send-log") as f:
    sent_packets = {int(line.split()[0]): float(line.split()[1]) for line in
                    f.readlines()}

for packet_id in sent_packets.keys():
    if packet_id in recv_packets.keys():
        delays[packet_id] = recv_packets[packet_id] - sent_packets[packet_id]
    else:
        print("Packet", packet_id, "not received.")

delays_lst = list(delays.values())
delays_len = len(delays.values())
delays_sum = sum(delays.values())
delays_srt = sorted(delays.values())

out_format = "Sum: {:.3f}s, Min: {:.3f}ms, Avg: {:.3f}ms, Median: {:.3f}ms, " \
             "Max: {:.3f}ms"

print()
print("Latency")
print(out_format.format(delays_sum, delays_srt[0] * 1000,
                        delays_sum / delays_len * 1000,
                        delays_srt[
                            delays_len // 2] * 1000,
                        delays_srt[-1] * 1000))
print()

jitter = [abs(delays_lst[i] - delays_lst[i + 1]) for i in range(delays_len - 1)]
jitter_srt = sorted(jitter)
jitter_sum = sum(jitter)
jitter_len = len(jitter)

print("Jitter")
print(out_format.format(jitter_sum,
                        jitter_srt[0] * 1000,
                        jitter_sum / jitter_len * 1000,
                        jitter_srt[
                            jitter_len // 2] * 1000,
                        jitter_srt[-1] * 1000))
print()

with open("/tmp/blub.csv", "w") as f:
    cntr = Counter([ceil(ms * 1000) for ms in delays_srt])
    for key in cntr.keys():
        f.write("{},{}\n".format(key, cntr[key]))

for key, value in delays.items():
    if value >= 1 or value <= 1/1000:
        print(key, value)
