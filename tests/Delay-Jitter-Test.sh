#!/usr/bin/env bash

PYTHONPATH="."

export PYTHONPATH

tests/Recv_and_answer.py 127.0.0.1:45000 >/dev/null &

RECV_PID="$!"

sleep 1

for i in {1..10}; do
    tests/Send_Random_Packets.py &
    RECV_PID="$RECV_PID $!"
done

mkdir -p tests/data tests/tmp

tests/Recv_Log.py 127.0.0.1:60001 > tests/tmp/recv-log &

RECV_PID="$RECV_PID $!"

sleep 1

tests/Replay_Log.py tests/data/discord_call_out > tests/tmp/send-log

sleep 3

kill $RECV_PID >/dev/null

tests/measure_delay.py