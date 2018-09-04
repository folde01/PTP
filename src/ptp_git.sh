#!/usr/bin/env bash
msg="$1"
git add ptp_*.py ptp_*.sh templates/*.html test-pcap-files/*.pcap
git commit -m "$msg"
git push origin master
