#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

resolving_domains_3(){
for domain in $(cat $host);
do
massdns -r $resolver -t A -o S -w /root/recon/$domain/subdomain/good/massdns_3.txt /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt
cat /root/recon/$domain/subdomain/good/massdns_3.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/$domain/subdomain/good/good_sub.txt
#shuffledns -d /root/recon/$domain/subdomain/good/finalsub.txt -r /root/wordlist/resolvers.txt -o /root/recon/$domain/subdomain/good/good_sub.txt
done
}
resolving_domains_3

domain_ip(){
for domain in $(cat $host);
do
gf ip /root/recon/$domain/subdomain/good/massdns_3.txt | sed 's/.*://' > /root/recon/$domain/subdomain/good/ip_sub.txt
done
}
domain_ip

http_prob(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/good_sub.txt | httpx -threads 200 -o /root/recon/$domain/subdomain/good/active_subdomain.txt 
done
}
http_prob

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

#SecretFinder(){
#for domain in $(cat $host);
#do
#cat /root/recon/$domain/url/final-url.txt | xargs -I@ sh -c 'python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i @' -o /root/recon/$domain/js_url/url_SecretFinder.html
#done
#}
#SecretFinder

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
#SecretFinder https://github.com/m4ll0k/SecretFinder
#Arjun https://github.com/s0md3v/Arjun

done
}
Get_js


#SecretFinder_js(){
#for domain in $(cat $host);
#do
#cat /root/recon/$domain/js_url/good_js_url.txt | xargs -I@ sh -c 'python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i @' -o /root/recon/$domain/js_url/js_SecretFinder.html
#done
#}
#SecretFinder_js

gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/redirect.txt
done
}
gf_patterns

SQL(){
for domain in $(cat $host);
do
cat /root/recon/$domain/gf/sqli.txt | nuclei -t /root/nuclei-templates/My-Nuclei-Templates/SQL/SQLInjection_ERROR.yaml -o sqlpoc.txt -v
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



