#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/Subomain-Takeover /root/recon/$domain/scan /root/recon/$domain/url /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL

subfinder -d $domain -o /root/recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/recon/$domain/subdomain/findomain.txt
sudomy -d $domain -o /root/recon/$domain/subdomain/sudomy.txt
amass enum -active -d $domain -o /root/recon/$domain/subdomain/amass_sub.txt
python3 /root/OK-VPS/tools/github-search/github-subdomains.py -t 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 -d $domain > /root/recon/$domain/subdomain/gitsub.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/recon/$domain/subdomain/crtsub.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/riddlersub.txt
curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee /root/recon/$domain/subdomain/bufferoversub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/recon/$domain/subdomain/altnamesub.txt
cat /root/recon/$domain/subdomain/*.txt > /root/recon/$domain/subdomain/allsub.txt
cat /root/recon/$domain/subdomain/allsub.txt | anew -q /root/recon/$domain/subdomain/all_srot_sub.txt
done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do
massdns -r $resolver -t A -o S -w /root/recon/$domain/subdomain/massdns.txt /root/recon/$domain/subdomain/all_srot_sub.txt
cat /root/recon/$domain/subdomain/massdns.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/$domain/subdomain/final_sub.txt
cp /root/recon/$domain/subdomain/final_sub.txt /root/recon/$domain/subdomain/good
done
}
resolving_domains



Recursive(){
for domain in $(cat $host);
do
cp Recursive.sh /root/recon/$domain/subdomain/good
cd /root/recon/$domain/subdomain/good
./Recursive.sh final_sub.txt
done
}
Recursive
