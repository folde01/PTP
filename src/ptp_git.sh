#!/usr/bin/env bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <commit message>"
    exit 1
fi

msg="$1"

git add ptp_*.py ptp_*.sh templates/*.html test-pcap-files/*.pcap
git commit -m "$msg"
git push origin master
