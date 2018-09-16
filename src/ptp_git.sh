#!/usr/bin/env bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <commit message>"
    exit 1
fi

msg="$1"

git add ptp_*.py
git add ptp_*.sh
git add templates/*.html
git add test-pcap-files/*.pcap
git add static/*.css
git add jupyter-notebooks/*.ipynb 

git commit -m "$msg"
git push origin master
