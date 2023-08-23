
#!/bin/bash

host=$1
resolver="/root/wordlist/resolvers.txt"
brut(){
for sub in $(cat $host);
do

puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt $sub -r /root/wordlist/resolvers.txt | anew -q /root/recon/indriver.com/subdomain/good/puredns.txt
cat *.txt > P_allsub.txt
cat P_allsub.txt | uniq -u > puredns_bruteforce_sub.txt

done
}
brut

