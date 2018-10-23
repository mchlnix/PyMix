#!/usr/bin/env bash

PYTHONPATH="."

export PYTHONPATH

mkdir -p tests/data tests/tmp

tests/Recv_Log.py 127.0.0.1:60001 > tests/tmp/recv-log &

RECV_PID="$!"

sleep 1

tests/Replay_Log.py tests/data/discord_call_out > tests/tmp/send-log

sleep 5

kill "$RECV_PID"

tests/measure_delay.py