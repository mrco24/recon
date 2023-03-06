
#!/bin/bash

host=$1

brut(){
for sub in $(cat $host);
do

puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt $sub -r /root/wordlist/resolvers.txt | anew -q /root/recon/$domain/subdomain/good/puredns.txt

done
}
brut
