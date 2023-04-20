#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

resolving_domains_3(){
for domain in $(cat $host);
do
massdns -r $resolver -t A -o S -w /root/recon/$domain/subdomain/good/massdns_3.txt /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt
cat /root/recon/$domain/subdomain/good/massdns_3.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/$domain/subdomain/good/good_sub.txt
#shuffledns -d /root/recon/$domain/subdomain/good/finalsub.txt -r /root/wordlist/resolvers.txt -o /root/recon/$domain/subdomain/good/resolv_sub.txt
done
}
resolving_domains_3

http_probe(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/resolv_sub.txt | httprobe -o /root/recon/$domain/subdomain/good/httprobe_subdomain.txt 
done
}
http_probe

Gen_subdomain(){
for domain in $(cat $host);
do
gotator -sub /root/recon/$domain/subdomain/good/httprobe_subdomain.txt -perm /root/wordlist/mrco24-wordlist/gen-sub-wordlist.txt -depth 3 > /root/recon/$domain/subdomain/good/Gen_sub/Gen_subdomain.txt | cat /root/recon/$domain/subdomain/good/Gen_sub/Gen_subdomain.txt | httpx -o /root/recon/$domain/subdomain/good/Gen_sub/httpx_gen_sub.txt
cp /root/recon/$domain/subdomain/good/httprobe_subdomain.txt /root/recon/$domain/subdomain/good/Gen_sub
cat /root/recon/$domain/subdomain/good/Gen_sub/*.txt > /root/recon/$domain/subdomain/good/Gen_sub/all-gen-sub.txt
cat /root/recon/$domain/url/all-gen-sub.txt | sort --unique | tee /root/recon/$domain/url/active_subdomain.txt
done
}
Gen_subdomain

domain_ip(){
for domain in $(cat $host);
do
gf ip /root/recon/$domain/subdomain/good/massdns_3.txt | sed 's/.*://' > /root/recon/$domain/subdomain/good/ip_sub.txt
done
}
domain_ip

Special_subdomain(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | anew /root/recon/$domain/Special_subdomain/Special_subdomain.txt 
done
}
Special_subdomain

Special_subdomain_scanner(){
for domain in $(cat $host);
do
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/cves/  -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-cves.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/vulnerabilities/  -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-vulnerabilities.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/technologies/  -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-technologies.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/ -o /root/recon/$domain/Special_subdomain/scan/nuclei/My-Nuclei-Templates.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/Nuclei 1/ -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-Nuclei.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t  nuclei -t /root/templates/my-nuclei-templates/workflows/ -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-workflows.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/helpers/ -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-helpers.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/idscan/ -o /root/recon/$domain/Special_subdomain/scan/nuclei/my-idscan.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/nuclei-templates/cves/ -o /root/recon/$domain/Special_subdomain/scan/new-nuclei/cve.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/nuclei-templates/vulnerabilities/  -o /root/recon/$domain/Special_subdomain/scan/new-nuclei/vulnerabilities.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/nuclei-templates/takeovers/ -o /root/recon/$domain/Special_subdomain/scan/new-nuclei/takover.txt -v
cat /root/recon/$domain/Special_subdomain/Special_subdomain.txt | nuclei -t /root/templates/nuclei-templates/technologies/ -o /root/recon/$domain/Special_subdomain/scan/new-nuclei/technologies.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/Special_subdomain/Special_subdomain.txt -o /root/recon/$domain/Special_subdomain/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/Special_subdomain/Special_subdomain.txt -o /root/recon/$domain/Special_subdomain/scan/jaeles/ -v
done
}
Special_subdomain_scanner

Special_subdomain_Dir(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/Special_subdomain/Special_subdomain.txt > /root/recon/$domain/dri/Special_subdomain_Dri.txt
done
}
Special_subdomain_Dir

open_port(){
for domain in $(cat $host);
do
naabu --list /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/open-port.txt
done
}
open_port

web_Screenshot(){
for domain in $(cat $host);
do
cd /root/recon/$domain/Subomain-Screenshots 
gowitness file -f /root/recon/$domain/subdomain/good/active_subdomain.txt
done
}
web_Screenshot

Subdomai_takeover(){
for domain in $(cat $host);
do
subzy run --targets /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt --concurrency  20 --hide_fails > /root/recon/$domain/Subomain-Takeover/poc.txt
done
}
Subdomai_takeover


CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/active_subdomain.txt > /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker

Fuzz(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/cloudflare_check.txt > /root/recon/$domain/dri/dri_cf.txt
done
}
Fuzz

FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/active_subdomain.txt  > /root/recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active

FUZZ_ip(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/ip_sub.txt  > /root/recon/$domain/dri/dri_ip.txt
done
}
FUZZ_ip

Dead_sbdomain(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt  > /root/recon/$domain/dri/dri_dead_subdomain.txt
done
}
Dead_sbdomain

vuln_scanner(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/cves/  -o /root/recon/$domain/scan/nuclei/my-cves.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/vulnerabilities/  -o /root/recon/$domain/nuclei/scan/my-vulnerabilities.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/technologies/  -o /root/recon/$domain/scan/nuclei/my-technologies.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/ -o /root/recon/$domain/scan/nuclei/My-Nuclei-Templates.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/Nuclei 1/ -o /root/recon/$domain/scan/nuclei/my-Nuclei.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t  nuclei -t /root/templates/my-nuclei-templates/workflows/ -o /root/recon/$domain/scan/nuclei/my-workflows.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/helpers/ -o /root/recon/$domain/scan/nuclei/my-helpers.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/my-nuclei-templates/idscan/ -o /root/recon/$domain/scan/nuclei/my-idscan.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/nuclei-templates/cves/ -o /root/recon/$domain/scan/new-nuclei/cve.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/nuclei-templates/vulnerabilities/  -o /root/recon/$domain/scan/vulnerabilities.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/nuclei-templates/takeovers/ -o /root/recon/$domain/scan/takover.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/templates/nuclei-templates/technologies/ -o /root/recon/$domain/scan/technologies.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/jaeles/ -v
done
}
vuln_scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | hakrawler | grep $domain > /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep $domain | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | gau --threads 5 > /root/recon/$domain/url/gau-urls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | httpx | katana -o /root/recon/$domain/url/katana.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt
cat /root/recon/$domain/url/*.txt > /root/recon/$domain/url/all-url.txt
cat /root/recon/$domain/url/all-url.txt | sort --unique | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/recon/$domain/url/valid_urls.txt
done
}
find_urls

SecretFinder(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/final-url.txt | while read url; do python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i $url -o cli >> /root/recon/$domain/js_url/url_SecretFinder.txt; done
done
}
SecretFinder

url_vuln_scanner(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | nuclei -t /root/templates/my-nuclei-templates/  -o /root/recon/$domain/scan/nuclei/urls_my_nuclei_scan.txt -v
cat /root/recon/$domain/url/valid_urls.txt | nuclei -t /root/templates/nuclei-templates/  -o /root/recon/$domain/scan/nuclei/urls_nuclei_scan.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/jaeles/ -v
done
}
url_vuln_scanner

Get_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/getjs_urls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/Domain_js_urls.txt
cat /root/recon/$domain/js_url/*.txt > /root/recon/$domain/js_url/all_js_url.txt
cat /root/recon/$domain/js_url/all_js_url.txt | sort --unique | tee /root/recon/$domain/js_url/fina_js_url.txt
cat /root/recon/$domain/js_url/fina_js_url.txt | httpx -threads 200 -o /root/recon/$domain/js_url/jshttpxurl.txt
cat /root/recon/$domain/js_url/jshttpxurl.txt | sort --unique | tee /root/recon/$domain/js_url/good_js_url.txt
/root/Tools/JSScanner/./script.sh /root/recon/$domain/js_url/jshttpxurl.txt
#relative-url-extractor https://github.com/jobertabma/relative-url-extractor
#LinkFinder https://github.com/GerbenJavado/LinkFinder
#Arjun https://github.com/s0md3v/Arjun

done
}
Get_js


SecretFinder_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/js_url/good_js_url.txt | while read url; do python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i $url -o cli >> /root/recon/$domain/js_url/js_SecretFinder.txt; done
done
}
SecretFinder_js

gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf my-lfi /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/my-lfi.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/rmy-lfiedirect.txt
gf aws-keys /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/aws-keys-json.txt
gf interestingsubs /root/recon/$domain/subdomain/good/active_subdomain.txt |  tee /root/recon/$domain/gf/interestingsubs.txt
gf s3-buckets /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/s3-buckets.txt
gf servers /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/servers.txt
gf debug-pages /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug-pages.txt
gf debug_logic /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug_logic.txt
gf img-traversal /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/img-traversal.txt
gf php-sources /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-sources.txt
gf upload-fields /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/upload-fields.txt
gf php-errors /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-errors.txt
gf http-auth /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/http-auth.txt
gf idor /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/idor.txt
gf interestingparams /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingparams.txt
gf interestingEXT /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingEXT.txt
gf rce /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/rce.txt
done
}
gf_patterns

SQL(){
for domain in $(cat $host);
do
sqlmap -m /root/recon/$domain/gf/sqli.txt --batch --risk 3  --random-agent | tee -a /root/recon/$domain/sql/sql_url.txt
sqlmap -m /root/recon/$domain/url/valid_urls.txt --batch --risk 3  --random-agent | tee -a /root/recon/$domain/sql/sql_url.txt

done
}
SQL


Refactors_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | Gxss -o /root/recon/$domain/xss/gxss.txt
cat /root/recon/$domain/url/valid_urls.txt | kxss > /root/recon/$domain/xss/kxss_url.txt
cat /root/recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/recon/$domain/xss/kxss_url_active.txt
cat /root/recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/recon/$domain/xss/dalfoxss.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh
done
}
Refactors_xss



