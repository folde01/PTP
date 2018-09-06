#!/usr/bin/env bash

# New ciphers are developed occasionally so this generates a python module 
# containing a table mapping the cipher codes which appear in the SSL handshake 
# to cipher names.
#
# The raw mappings come from a file downloaded from the openssl code base, and then
# sed is used to make the python module for PTP to use.

RAW_MAPPING_URL='https://raw.githubusercontent.com/openssl/openssl/d6c46adf180aa3e29d5dac075fb673bbc273ae08/ssl/t1_trce.c'

RAW_MAPPING_FILE='cipher_code_raw_mappings.txt'

wget -N $RAW_MAPPING_URL -O $RAW_MAPPING_FILE

PTP_CIPHER_MODULE='ptp_ssl_ciphers.py'

(

echo 'ssl_ciphers = {'

cat "$RAW_MAPPING_FILE" | sed -n -e '/ssl_ciphers_tbl/,/ssl_comp_tbl/p' -e '/ssl_comp_tbl/q' | grep 0x | awk -Fx '{print $2}' | sed 's/..$//' | sed 's/ //' | sed 's/\(.*\),\(.*\)/    "\L\1\E\": \2,/'

echo '}'

) > $PTP_CIPHER_MODULE
