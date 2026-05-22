#!/bin/bash
cd /home/youssef-amr/soc_project || exit 1

python3 packet_capture_live_writer.py

inotifywait -m -e modify,close_write,create,move /var/log/auth.log 2>/dev/null |
while read line; do
  python3 packet_capture_live_writer.py
done
