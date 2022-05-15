#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

resolving_domains_2(){
for domain in $(cat $host);
do
massdns -r $resolver -t A -o S -w /root/recon/$domain/subdomain/good/massdns.txt /root/recon/$domain/subdomain/good/finalsub.txt
cat /root/recon/$domain/subdomain/good/massdns.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | tee > /root/recon/$domain/subdomain/good/good_sub.txt
done
}
resolving_domains_2

domain_ip(){
for domain in $(cat $host);
do
gf ip /root/recon/$domain/subdomain/good/massdns.txt | sed 's/.*://' > /root/recon/$domain/subdomain/good/ip_sub.txt
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

php_info(){
for domain in $(cat $host);
do
cat sub.txt | httpx -path /phpinfo.php -status-code -content-length -title > /root/recon/$domain/scan/php.txt
done
}
php_info

Subdomai_takeover(){
for domain in $(cat $host);
do
subzy -targets /root/recon/$domain/subdomain/good/active_subdomain.txt > /root/recon/$domain/Subomain-Takeover/poc.txt
done
}
Subdomai_takeover

web_Screenshot(){
for domain in $(cat $host);
do
gowitness file -f /root/recon/$domain/subdomain/good/active_subdomain.txt
done
}
web_Screenshot

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/active_subdomain.txt > /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker

Find_Web_Technologies(){
for domain in $(cat $host);
do
python3 /root/OK-VPS/tools/wappalyzer-cli/src/wappy -f /root/recon/$domain/subdomain/good/active_subdomain.txt > /root/recon/$domain/scan/new-technologies.txt
done
}
Find_Web_Technologies

scanner(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o /root/recon/$domain/scan/nuclei/new-cves.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o /root/recon/$domain/nuclei/scan/new-vulnerabilities.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o /root/recon/$domain/scan/nuclei/technologies.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/My-Nuclei-Templates/ -o /root/recon/$domain/scan/nuclei/My-Nuclei-Templates.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/Nuclei 1/ -o /root/recon/$domain/scan/nuclei/Nuclei.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t  nuclei -t /root/nuclei-templates/workflows/ -o /root/recon/$domain/scan/nuclei/workflows.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/helpers/ -o /root/recon/$domain/scan/nuclei/helpers.txt -v
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | nuclei -t /root/nuclei-templates/idscan/ -o /root/recon/$domain/scan/nuclei/idscan.txt -v
done
}
scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | hakrawler | grep $domain > /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep $domain | tee /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | gau --threads 5 > /root/recon/$domain/url/gau-urls.txt
cat /root/recon/$domain/url/*.txt > /root/recon/$domain/url/all-url.txt
cat /root/recon/$domain/url/all-url.txt | sort --unique | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/recon/$domain/url/valid_urls.txt
done
}
find_urls


Get_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | getJS --complete | tee /root/recon/$domain/js_url/getjs_urls.txt
cat /root/recon/$domain/url/valid_urls.tx | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript' | tee /root/recon/$domain/js_url/jshttpxurl.txt
done
}
Get_js

gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
done
}
gf_patterns

Refactors_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | Gxss -o /root/recon/$domain/xss/gxss.txt
cat /root/recon/$domain/url/valid_urls.txt | kxss > /root/recon/$domain/xss/kxss_url.txt
cat /root/recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/recon/$domain/xss/kxss_url_active.txt
cat /root/recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/recon/$domain/xss/dalfoxss.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh > root/recon/$domain/xss/Dom_xss.txt
done
}
Refactors_xss

SQL(){
for domain in $(cat $host);
do
sqlmap -m /root/recon/$domain/gf/sqli.txt --batch --random-agent --level 1 | tee /root/recon/$domain/SQL/sqlpoc.txt -v
done
}
SQL

LFI(){
for domain in $(cat $host);
do
cat /root/recon/$domain/gf/lfi.txt | qsreplace FUZZ | while read url ; do ffuf -u $url -mr "root:x" -w ~/tools/lfipayloads.txt -of csv -o $domain/vulnerabilities/LFI/lfi.txt -t 50 -c  ; done
done
}
LFI

Git_dork(){
for domain in $(cat $host);
do
export GITHUB_TOKEN=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
python3 /root/Okvps/tools/GitDorker/GitDorker.py -tf /root/Okvps/tools/GitDorker/token.txt -q $domain -d /root/Okvps/tools/GitDorker/Dorks/medium_dorks.txt -o /root/recon/$domain/git_dork/medium_dorks.txt
done
}
Git_dork
