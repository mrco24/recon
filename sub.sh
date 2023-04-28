#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/subdomain/good/Gen_sub /root/recon/$domain/Subomain-Takeover /root/recon/$domain/Subomain-Screenshots /root/recon/$domain/Special_subdomain /root/recon/$domain/Special_subdomain/scan /root/recon/$domain/scan  /root/recon/$domain/scan/my-jaeles /root/recon/$domain/scan/jaeles /root/recon/$domain/scan/jaeles/my-url /root/recon/$domain/scan/jaeles/url /root/recon/$domain/dri  /root/recon/$domain/scan/nuclei/Php-My-Admin /root/recon/$domain/scan/nuclei /root/recon/$domain/scan/new-nuclei /root/recon/$domain/url /root/recon/$domain/Secret-api /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/sql /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL

subfinder -d $domain -all -o /root/recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/recon/$domain/subdomain/findomain.txt
#sudomy -d $domain -o /root/recon/$domain/subdomain/sudomy.txt
amass enum -active -d $domain -o /root/recon/$domain/subdomain/amass_sub.txt
amass enum -passive -d $domain -o /root/recon/$domain/subdomain/amass_sub_passive.txt
chaos -d $domain -o /root/recon/$domain/subdomain/chaos_sub.txt
/root/OK-VPS/tools/Lilly/./lilly.sh -d $domain -a hLRieliNwbe2vJf8TEXo3keLG2pZcdIP | tee -a /root/recon/$domain/subdomain/lilly_shodan.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/recon/$domain/subdomain/web.archive.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/recon/$domain/subdomain/crtsub.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/riddlersub.txt
curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee /root/recon/$domain/subdomain/bufferoversub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/recon/$domain/subdomain/altnamesub.txt
shuffledns -d $domain -w $wordlist -r /root/wordlist/resolvers.txt -o /root/recon/$domain/subdomain/shuffledns.txt
cat /root/recon/$domain/subdomain/*.txt > /root/recon/$domain/subdomain/allsub.txt
cat /root/recon/$domain/subdomain/allsub.txt | uniq -u > /root/recon/$domain/subdomain/all_srot_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do
massdns -r $resolver -t A -o S -w /root/recon/$domain/subdomain/massdns.txt /root/recon/$domain/subdomain/all_srot_sub.txt
cat /root/recon/$domain/subdomain/massdns.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/$domain/subdomain/good/massdns_live_sub.txt
cd  /root/recon/$domain/subdomain/good
cat massdns_live_sub.txt | uniq -u > passive_resolving_live_sub.txt
#shuffledns -d /root/recon/$domain/subdomain/all_srot_sub.txt -r /root/wordlist/resolvers.txt -o  /root/recon/$domain/subdomain/good/passive_resolving_live_sub.txt
done
}
resolving_domains

#brut(){
#for domain in $(cat $host);
#do
#cp brut.sh /root/recon/$domain/subdomain/good
#cd /root/recon/$domain/subdomain/good
#./brut.sh passive_resolving_live_sub.txt
#done
#}
#brut

Recursive(){
for domain in $(cat /root/recon/$host);
do
cp /root/recon/Recursive.sh /root/recon/$domain/subdomain/good/
cd /root/recon/$domain/subdomain/good
./Recursive.sh passive_resolving_live_sub.txt
done
}
Recursive

recon(){
for domain in $(cat /root/recon/$host);
do
cd /root/recon && ./recon.sh /root/recon/$host
done
}
recon
