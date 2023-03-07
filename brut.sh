
#!/bin/bash

host=$1
resolver="/root/wordlist/resolvers.txt"
brut(){
for sub in $(cat $host);
do

puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt $sub -r /root/wordlist/resolvers.txt | anew -q /root/recon/indriver.com/subdomain/good/puredns.txt
cat *.txt > P_allsub.txt
cat P_allsub.txt | anew -q puredns_bruteforce_sub.txt

done
}
brut

resolving_domains_2(){
for sub in $(cat $host);
do

massdns -r $resolver -t A -o S -w /root/recon/indriver.com/subdomain/good/massdns_2.txt /root/recon/indriver.com/subdomain/good/puredns_bruteforce_sub.txt
cat /root/recon/indriver.com/subdomain/good/massdns_2.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/indriver.com/subdomain/good/puredns_good_sub.txt
#shuffledns -d /root/recon/$domain/subdomain/good/finalsub.txt -r /root/wordlist/resolvers.txt -o /root/recon/$domain/subdomain/good/puredns_good_sub.txt
done
}
resolving_domains_2
