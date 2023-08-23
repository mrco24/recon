#!/bin/bash

host=$1
resolver="/root/wordlist/resolvers.txt"
brut(){
for sub in $(cat $host);
do
puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt $sub -r /root/wordlist/resolvers.txt | tee -a puredns_sub.txt
done
}
brut
