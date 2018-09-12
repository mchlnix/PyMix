#!/usr/bin/python3 -u
from TwoWayTable import TwoWayTable, PairedDict

key = "Key"
value = "Value"

# PairedDict

dict1 = {}
dict2 = {}

pd = PairedDict(dict1, dict2)

pd[key] = value

assert dict1[key] == value
assert dict2[value] == key

del pd[key]

assert key not in dict1
assert value not in dict2

dict1[key] = value

assert key in dict1
assert value not in dict2

# TwoWayTable

chan_id = "12345"
ip = "127.0.0.1:12345"

twt = TwoWayTable("channel", "ip")

twt.channel[ip] = chan_id

assert ip in twt.ips
assert chan_id in twt.channels

del twt.ip[chan_id]

assert chan_id not in twt.channels
assert ip not in twt.ips

del twt

## Test that the keys in the dicts are not limited by each other

in_chan_a = 12345
out_chan_a = 54321
in_chan_b = out_chan_a
out_chan_b = 99999

twt = TwoWayTable("in_channel", "out_channel")

twt.in_channel[out_chan_a] = in_chan_a
twt.in_channel[out_chan_b] = in_chan_b

assert in_chan_a in twt.in_channels
assert in_chan_b in twt.in_channels
assert out_chan_a in twt.out_channels
assert out_chan_b in twt.out_channels

assert in_chan_a not in twt.out_channels
assert out_chan_b not in twt.in_channels
