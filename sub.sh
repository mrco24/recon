#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/subdomain/good/fainal /root/recon/$domain/Subomain-Takeover /root/recon/$domain/Subomain-Screenshots /root/recon/$domain/Special_subdomain /root/recon/$domain/Special_subdomain/scan /root/recon/$domain/scan  /root/recon/$domain/scan/my-jaeles /root/recon/$domain/scan/jaeles /root/recon/$domain/scan/jaeles/my-url /root/recon/$domain/scan/jaeles/url /root/recon/$domain/dri  /root/recon/$domain/scan/nuclei/Php-My-Admin /root/recon/$domain/scan/nuclei /root/recon/$domain/scan/new-nuclei /root/recon/$domain/url /root/recon/$domain/Secret-api /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/sql /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL

subfinder -all -d $domain -o /root/recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/recon/$domain/subdomain/assetfinder.txt 
findomain -t $domain | tee /root/recon/$domain/subdomain/findomain.txt
github-subdomains -t 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 -d $domain -o /root/recon/$domain/subdomain/github_sub.txt
#sudomy -d $domain -o /root/recon/$domain/subdomain/sudomy.txt
amass enum -passive -d $domain -o /root/recon/$domain/subdomain/amass_sub_passive.txt
export CENSYS_API_ID=303b2554-31b0-4e2d-a036-c869f23bfb76
export CENSYS_API_SECRET=sB8T2K8en7LW6GHOkKPOfEDVpdmaDj6t
python /root/OK-VPS/tools/censys-subdomain-finder/censys-subdomain-finder.py $domain -o /root/recon/$domain/subdomain/censys_subdomain.txt
#knockpy --no-http logitech.com 
export CHAOS_KEY=8153077428be89cccb4f3f7e20f45a166c0f5565d9cb118b7c529a5d9ee5bd00
chaos -d $domain -o /root/recon/$domain/subdomain/chaos_sub.txt
/root/OK-VPS/tools/Lilly/./lilly.sh -d $domain -a F3WxribTVzWz8He9zrtNrGwGl7jDepty | tee -a /root/recon/$domain/subdomain/lilly_shodan.txt
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
puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/subdomains-top1million-5000.txt $domain -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/puredns_sub.txt
cat /root/recon/$domain/subdomain/*.txt | sort --unique | grep $domain | tee -a /root/recon/$domain/subdomain/all_srot_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/all_srot_sub.txt -threads 50 -o /root/recon/$domain/subdomain/good/passive_resolving_live_sub.txt
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
cp /root/recon/web_archive_urls.sh /root/recon/$domain/url/
cp /root/recon/Recursive.sh /root/recon/$domain/subdomain/good/
cd /root/recon/$domain/subdomain/good
./Recursive.sh passive_resolving_live_sub.txt
done
}
Recursive

resolving_domains_1(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt -threads 40 -o /root/recon/$domain/subdomain/good/good_sub.txt
done
}
resolving_domains_1

Gen_subdomain(){
for domain in $(cat $host);
do
gotator -sub /root/recon/$domain/subdomain/good/good_sub.txt -perm /root/wordlist/mrco24-wordlist/gen-sub-wordlist.txt -depth 1 | tee -a /root/recon/$domain/subdomain/good/Gen_subdomain.txt
cat /root/recon/$domain/subdomain/good/Gen_subdomain.txt | sort --unique | grep $domain | tee -a /root/recon/$domain/subdomain/good/take_ge_subdomain.txt
cat /root/recon/$domain/subdomain/good/*.txt |sort --unique | tee -a /root/recon/$domain/subdomain/good/ip_chack_allsub.txt
cat /root/recon/$domain/subdomain/good/ip_chack_allsub.txt | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/domain_ip.txt
shodan search  ssl.cert.subject.CN:"$domain.*" 200 | awk '{print $1}' | httpx | tee -a /root/recon/$domain/subdomain/good/shodan_ip.txt
cat /root/recon/$domain/subdomain/good/*.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/all_srot_sub.txt
httpx -l /root/recon/$domain/subdomain/good/all_srot_sub.txt -o /root/recon/$domain/subdomain/good/httpx_sub.txt
cat /root/recon/$domain/subdomain/good/httpx_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/wihtout_duplicat_for_brut_sub.txt
cat /root/recon/$domain/subdomain/good/fainal/wihtout_duplicat_for_brut_sub.txt | sed 's#\(https\?://\)##' | tee -a /root/recon/$domain/subdomain/good/fainal/root/recon/$domain/subdomain/good/fainal/http_domain_for_brut.txt
done
}
Gen_subdomain

sub_brutforche(){
for domain in $(cat $host);
do
puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt -d /root/recon/$domain/subdomain/good/fainal/http_domain_for_brut.txt -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/fainal/purdns_sub.txt
done
}
sub_brutforche

httpx_resolve(){
for domain in $(cat $host);
do
#altdns -i /root/recon/$domain/subdomain/good/puredns/httpx_sub.txt -o data_output -w $wordlist -r -s /root/recon/$domain/subdomain/good/fainal/altdns_sub.txt
#/root/OK-VPS/tools/subbrute-77/./subbrute.py -s /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt -t /root/recon/$domain/subdomain/good/fainal/httpx_sub.txt -o /root/recon/$domain/subdomain/good/fainal/subbrute_sub.txt -v
#rm -r fainal/http_domain_for_brut.txt
cat /root/recon/$domain/subdomain/good/fainal/http_domain_for_brut.txt | analyticsrelationships | tee -a /root/recon/$domain/subdomain/good/fainal/httpx_sub.txt -o /root/recon/$domain/subdomain/good/fainal/fainal/analyticsrelationships_sub.txt
cat /root/recon/$domain/subdomain/good/fainal/*.txt |sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/all_king_sub.txt
httpx -l /root/recon/$domain/subdomain/good/fainal/all_king_sub.txt -o /root/recon/$domain/subdomain/good/fainal/king_httpx_sub.txt
cat /root/recon/$domain/subdomain/good/fainal/king_httpx_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt 
done
}
httpx_resolve

interesting_subs(){
for domain in $(cat $host);
do
gf interestingsubs /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | tee /root/recon/$domain/subdomain/good/interestingsubs.txt 
done
}
interesting_subs 

recon(){
for domain in $(cat /root/recon/$host);
do
cd /root/recon
./recon.sh /root/recon/$host
done
}
recon
