#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

resolving_domains(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt -threads 50 -o /root/recon/$domain/subdomain/good/good_sub.txt
done
}
resolving_domains

Gen_subdomain(){
for domain in $(cat $host);
do
gotator -sub /root/recon/$domain/subdomain/good/good_sub.txt -perm /root/wordlist/mrco24-wordlist/gen-sub-wordlist.txt -depth 1 | tee -a /root/recon/$domain/subdomain/good/Gen_subdomain.txt
cat /root/recon/$domain/subdomain/good/Gen_subdomain.txt | sort --unique | grep $domain | tee -a /root/recon/$domain/subdomain/good/take_ge_subdomain.txt
cat /root/recon/$domain/subdomain/good/*.txt > /root/recon/$domain/subdomain/good/allsub.txt
cat /root/recon/$domain/subdomain/good/allsub.txt | uniq -u | grep $domain | tee -a /root/recon/$domain/subdomain/good/all_srot_sub.txt
done
}
Gen_subdomain

httpx_resolve(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/good/all_srot_sub.txt -threads 50 -o /root/recon/$domain/subdomain/good/active_subdomain.txt 
done
}
httpx_resolve

interesting_subs(){
for domain in $(cat $host);
do
gf interestingsubs /root/recon/$domain/subdomain/good/active_subdomain.txt | tee /root/recon/$domain/subdomain/good/interestingsubs.txt 
done
}
interesting_subs 

nrich_cve(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | dnsx -a -resp-only | nrich -  | tee -a /root/recon/$domain/scan/nrich_cve.txt 
done
}
nrich_cve 

Subdomai_takeover(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/take_ge_subdomain.txt -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/subdomain-takeover/subdomain-takeover_detect-all-takeovers.yaml -c 100 -o /root/recon/$domain/Subomain-Takeover/poc.txt -v
done
}
Subdomai_takeover

open_port(){
for domain in $(cat $host);
do
naabu -list /root/recon/$domain/subdomain/good/active_subdomain.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/open-port.txt
naabu -list /root/recon/$domain/subdomain/good/active_subdomain.txt -p - -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/filter-all-open-port.txt
done
}
open_port

#web_Screenshot(){
#for domain in $(cat $host);
#do
#cd /root/recon/$domain/Subomain-Screenshots 
#gowitness file -f /root/recon/$domain/subdomain/good/active_subdomain.txt
#done
#}
#web_Screenshot

Http-Request-Smugglingr(){
for domain in $(cat $host);
do
cd /root/OK-VPS/tools/http-request-smuggling | python3 smuggle.py -urls /root/recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/recon/$domain/scan/Http-Request-Smugglingr.txt
done
}
Http-Request-Smugglingr

Php_My_Admin(){
for domain in $(cat $host);
do
nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/php-my-admin/phpadmin.yaml -l /root/recon/$domain/subdomain/good/active_subdomain.txt -c 50  -o /root/recon/$domain/scan/nuclei/Php-My-Admin/php_admin.txt -v
done
}
Php_My_Admin

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker


vuln_scanner(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/active_subdomain.txt -t /root/templates/my-nuclei-templates/ -c 50 -o /root/recon/$domain/scan/nuclei/my-all.txt -v
nuclei -l /root/recon/$domain/subdomain/good/active_subdomain.txt -t /root/nuclei-templates/ -c 50 -o /root/recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/active_subdomain.txt -o /root/recon/$domain/scan/jaeles/ -v
done
}
vuln_scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt |  gauplus -t 40 | tee -a /root/recon/$domain/url/gaplus-urls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | hakrawler | tee -a /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | katana -o /root/recon/$domain/url/katana.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt
cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/active_subdomain.txt
cat /root/recon/$domain/url/*.txt > /root/recon/$domain/url/all-url.txt
cat /root/recon/$domain/url/all-url.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/sort-url.txt
arjun -i /root/recon/$domain/url/sort-url.txt -t 30 -oT /root/recon/$domain/url/arjun.txt
cat /root/recon/$domain/url/*.txt | tee -a /root/recon/$domain/url/2all-url.txt
uro -i /root/recon/$domain/url/all-url.txt -o /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> /root/recon/$domain/url/valid_urls.txt
done
}
find_urls

Url_endpoints(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/final-url.txt | cut -d "/" -f4- >> /root/recon/$domain/url/url_endpoints.txt
done
}
Url_endpoints


gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf my-lfi /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/my-lfi.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/my-Redirect.txt
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
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/error-based-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/error-based-sql-injection.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/SQLInjection_ERROR.yaml -c 100  -o /root/recon/$domain/sql/SQLInjection_ERROR.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-time-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/header-blind-time-sql-injection.txt -v
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-sql-injection.yaml -c 100  -o /root/recon/$domain/sql/header-blind-sql-injection.txt -v
sqlmap -m /root/recon/$domain/url/valid_urls.txt --batch --risk 3  --random-agent | tee -a /root/recon/$domain/sql/sqlmap_sql_url.txt
done
}
SQL


Refactors_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | Gxss -o /root/recon/$domain/xss/gxss.txt
cat /root/recon/$domain/url/valid_urls.txt | kxss | tee -a  /root/recon/$domain/xss/kxss_url.txt
cat /root/recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/recon/$domain/xss/kxss_url_active.txt
cat /root/recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/recon/$domain/xss/kxss_dalfoxss.txt
cat /root/recon/$domain/xss/gxss.txt | dalfox pipe | tee /root/recon/$domain/xss/gxss_dalfoxss.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh
done
}
Refactors_xss

Bilnd_xss(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100  -o /root/recon/$domain/xss/header_blind_xss.txt -v
done
}
Bilnd_xss

Dom_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh | tee -a /root/recon/$domain/xss/Dom_xss.txt
done
}
Dom_xss

dir-traversal(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/dir-traversal.yaml -c 60  -o /root/recon/$domain/scan/nuclei/dir-traversal.txt -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header -v
jaeles scan -c 50 -s /root/templates/best/lfi-param-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-param -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-windows-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header-windows -v
done
}
dir-traversal

Nuclei_Redirect(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/gf/my-Redirect.txt -t /root/templates/fuzzing-templates/ -c 60  -o /root/recon/$domain/scan/nuclei/Redirect.txt -v
done
}
Nuclei Fuzz_Endpoint

Nuclei_Redirect(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/fuzzing-templates/redirect/open-redirect.yaml -c 60  -o /root/recon/$domain/scan/nuclei/urls_fuzzing-templates__scan.txt -v
done
}
Nuclei Fuzz_Endpoint

Fuzz_Endpoint(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/active_subdomain.txt -w /root/recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/recon/$domain/dri/Endpoint_Dir.txt
done
}
Fuzz_Endpoint

FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/active_subdomain.txt | tee -a /root/recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active

ip_sub(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/subdomain_ip.txt
dirsearch -l /root/recon/$domain/subdomain/good/subdomain_ip.txt | tee -a /root/recon/$domain/dri/sub_ip_dri_activ.txt
do ne
}
ip_sub

Nucli_fuzz(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/active_subdomain.txt -t /root/templates/fuzzing-templates/ -c 50  -o /root/recon/$domain/scan/nuclei/Domain_fuzzing-templates__scan.txt -v
done
}
Nucli_fuzz

Get_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/getjs_urls.txt
cat /root/recon/$domain/subdomain/good/active_subdomain.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/Domain_js_urls.txt
cat /root/recon/$domain/js_url/*.txt > /root/recon/$domain/js_url/all_js_url.txt
cat /root/recon/$domain/js_url/all_js_url.txt | sort --unique | tee /root/recon/$domain/js_url/fina_js_url.txt
cat /root/recon/$domain/js_url/fina_js_url.txt | httpx -threads 150 -o /root/recon/$domain/js_url/jshttpxurl.txt
cat /root/recon/$domain/js_url/jshttpxurl.txt | sort --unique | tee /root/recon/$domain/js_url/good_js_url.txt
/root/Tools/JSScanner/./script.sh /root/recon/$domain/js_url/jshttpxurl.txt
#relative-url-extractor https://github.com/jobertabma/relative-url-extractor
#LinkFinder https://github.com/GerbenJavado/LinkFinder
#Arjun https://github.com/s0md3v/Arjun

done
}
Get_js

#SecretFinder_js(){
#for domain in $(cat $host);
#do
#cat /root/recon/$domain/js_url/good_js_url.txt | while read url; do python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i $url -o cli >> /root/recon/$domain/js_url/js_SecretFinder.txt; done
#done
#}
#SecretFinder_js


