#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/subdomain/good/fainal /root/recon/$domain/subdomain/good/fainal/best /root/recon/$domain/Subomain-Takeover /root/recon/$domain/Subomain-Screenshots /root/recon/$domain/Special_subdomain /root/recon/$domain/Special_subdomain/scan /root/recon/$domain/scan  /root/recon/$domain/scan/my-jaeles /root/recon/$domain/scan/jaeles /root/recon/$domain/scan/jaeles/my-url /root/recon/$domain/scan/jaeles/url /root/recon/$domain/dri  /root/recon/$domain/scan/nuclei/Php-My-Admin /root/recon/$domain/scan/nuclei /root/recon/$domain/scan/new-nuclei /root/recon/$domain/url /root/recon/$domain/Secret-api /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/sql /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL

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
python3 /root/OK-VPS/tools/ctfr/ctfr.py -d $domain -o /root/recon/$domain/subdomain/crt_sub.txt
cero $domain | sed 's/^*.//' | grep -e "\." | sort -u | tee -a /root/recon/$domain/subdomain/cero_ssl_sub.txt
gau --threads 5 --subs $domain |  unfurl -u domains | sort -u -o /root/recon/$domain/subdomain/gau_subdomain.txt
waybackurls $domain |  unfurl -u domains | sort -u -o /root/recon/$domain/subdomain/waybackurl_subdomain.txt
/root/OK-VPS/tools/Lilly/./lilly.sh -d $domain -a F3WxribTVzWz8He9zrtNrGwGl7jDepty | tee -a /root/recon/$domain/subdomain/lilly_shodan.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/recon/$domain/subdomain/web.archive.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/riddlersub.txt
curl 'https://tls.bufferover.run/dns?q=.$domain' -H 'x-api-key: pYahDe96ByRcoscUPuHA9OP5hggjzlzag0gGTzch'| jq -r .Results[] | cut -d ',' -f5 | grep -F ".$domain" | tee -a /root/recon/$domain/subdomain/bufferover_sub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee /root/recon/$domain/subdomain/altnamesub.txt
cat /root/recon/$domain/subdomain/*.txt | sort --unique | grep $domain | tee -a /root/recon/$domain/subdomain/all_srot_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/all_srot_sub.txt -threads 50 -o /root/recon/$domain/subdomain/good/live_sub.txt
done
}
resolving_domains


