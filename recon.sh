#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"

resolving_domains_tow(){
for domain in $(cat $host);
do
httpx -l /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt -threads 40 -o /root/recon/$domain/subdomain/good/good_sub.txt
cat /root/recon/$domain/subdomain/good/good_sub.txt | sed 's#\(https\?://\)##' | tee -a /root/recon/$domain/subdomain/good/good_sub_remov_https.txt
done
}
resolving_domains_tow

Gen_subdomain(){
for domain in $(cat $host);
do
gotator -sub /root/recon/$domain/subdomain/good/good_sub_remov_https.txt -perm /root/wordlist/mrco24-wordlist/gen-sub-wordlist.txt -depth 1 -numbers 10 -mindup -adv -md | tee -a /root/recon/$domain/subdomain/good/Gen_subdomain.txt
cat /root/recon/$domain/subdomain/good/Gen_subdomain.txt | sort --unique | grep $domain | tee -a /root/recon/$domain/subdomain/good/take_ge_subdomain.txt
shodan search  ssl.cert.subject.CN:"$domain.*" 200 | awk '{print $1}' | httpx | tee -a /root/recon/$domain/subdomain/good/shodan_ip.txt
cat /root/recon/$domain/subdomain/good/*.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/all_srot_sub.txt
httpx -l /root/recon/$domain/subdomain/good/all_srot_sub.txt -o /root/recon/$domain/subdomain/good/httpx_sub.txt
cat /root/recon/$domain/subdomain/good/httpx_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/wihtout_duplicat_for_brut_sub.txt
cat /root/recon/$domain/subdomain/good/fainal/wihtout_duplicat_for_brut_sub.txt | sed 's#\(https\?://\)##' | tee -a /root/recon/$domain/subdomain/good/fainal/http_domain_for_brut.txt
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
httpx -l /root/recon/$domain/subdomain/good/fainal/best/all_king_sub.txt -o /root/recon/$domain/subdomain/good/fainal/best/king_httpx_good_sub.txt
cat root/recon/$domain/subdomain/good/fainal/best/king_httpx_good_sub.txt | dnsx -a -resp-only | tee -a root/recon/$domain/subdomain/good/fainal/best/domain_ip.txt
cat /root/recon/$domain/subdomain/good/fainal/best/king_httpx_good_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/best/sub_brutforche_2_file.txt 
done
}
httpx_resolve

wordlist_Making(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/fainal/best/sub_brutforche_2_file.txt | tok | anew | tee -a  /root/wordlist/my_wordlist.txt
done
}
wordlist_Making

sub_brutforche_2(){
for domain in $(cat $host);
do
puredns bruteforce /root/wordlist/my_wordlist.txt -d /root/recon/$domain/subdomain/good/fainal/best/sub_brutforche_2_file.txt -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/fainal/best/my_wordlist_purdns_sub.txt
done
}
sub_brutforche_2

httpx_resolve_2(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/domain_ip.txt
cat /root/recon/$domain/subdomain/good/fainal/best/*.txt |sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/best/best_all_king_sub.txt
httpx -l /root/recon/$domain/subdomain/good/fainal/best/best_all_king_sub.txt -o /root/recon/$domain/subdomain/good/fainal/best/best_king_httpx_sub.txt
cat /root/recon/$domain/subdomain/good/fainal/best/best_king_httpx_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt 
done
}
httpx_resolve_2


interesting_subs(){
for domain in $(cat $host);
do
gf interestingsubs /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | tee /root/recon/$domain/subdomain/good/fainal/best/interestingsubs.txt 
done
}
interesting_subs 

nrich_cve(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | dnsx -a -resp-only | nrich -  | tee -a /root/recon/$domain/scan/nrich_cve.txt 
done
}
nrich_cve 

Xray(){
for sub in $(cat  /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt);
do
cd /root/OK-VPS/tools/xray
./xray_linux_amd64 ws --basic-crawler $sub --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho Vun.html
done
}
Xray

Subdomai_takeover(){
for domain in $(cat $host);
do
cp -r /root/recon/$domain/subdomain/all_srot_sub.txt /root/recon/$domain/Subomain-Takeover
cp -r /root/recon/$domain/subdomain/good/Recursive_finalsub_all.txt /root/recon/$domain/Subomain-Takeover
cp -r /root/recon/$domain/subdomain/good/all_srot_sub.txt /root/recon/$domain/Subomain-Takeover
cp -r /root/recon/$domain/subdomain/good/fainal/all_king_sub.txt /root/recon/$domain/Subomain-Takeover
cp -r /root/recon/$domain/subdomain/good/fainal/best/best_all_king_sub.txt /root/recon/$domain/Subomain-Takeover
cd /root/recon/$domain/Subomain-Takeover
cat /root/recon/$domain/Subomain-Takeover/*.txt | sort --unique | tee -a /root/recon/$domain/Subomain-Takeover/subdomain_takeover.txt
subzy run --targets /root/recon/$domain/Subomain-Takeover/subdomain_takeover.txt | tee -a sub_poc.txt
nuclei -l /root/recon/$domain/Subomain-Takeover/subdomain_takeover.txt -t /root/templates/my-nuclei-templates/subdomain-takeover_detect-all-takeovers.yaml -c 100 -o /root/recon/$domain/Subomain-Takeover/poc.txt -v
cd
done
}
Subdomai_takeover

open_port(){
for domain in $(cat $host);
do
sed 's/https\?:\/\///' /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt | tee -a /root/recon/$domain/subdomain/good/fainal/best/sub_open_prot.txt
unimap --fast-scan --file /root/recon/$domain/subdomain/good/fainal/best/sub_open_prot.txt --ports "81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672" | tee -a /root/recon/$domain/scan/open_port.txt
#naabu -rate 10000 -list /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt 
#nmap -iL /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt -T5 | tee -a /root/recon/$domain/scan/open_port_nmap.txt
#naabu -list /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/open_port.txt
#naabu -list /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -p - -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/filter_all_open_port.txt
done
}
open_port

#web_Screenshot(){
#for domain in $(cat $host);
#do
#cd /root/recon/$domain/Subomain-Screenshots 
#gowitness file -f /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt 
#done
#}
#web_Screenshot

#Http-Request-Smugglingr(){
#for domain in $(cat $host);
#do
#cd /root/OK-VPS/tools/http-request-smuggling | python3 smuggle.py -urls /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | tee -a /root/recon/$domain/scan/Http-Request-Smugglingr.txt
#}
#Http-Request-Smugglingr

Php_My_Admin(){
for domain in $(cat $host);
do
nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/php-my-admin/phpadmin.yaml -l /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -c 50  -o /root/recon/$domain/scan/nuclei/Php-My-Admin/php_admin.txt -v
done
}
Php_My_Admin

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | tee -a /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker


vuln_scanner(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -t /root/templates/my-nuclei-templates/ -c 50 -o /root/recon/$domain/scan/nuclei/my-all.txt -v
nuclei -l /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -t /root/templates/fuzzing-templates/ -c 50 -o /root/recon/$domain/scan/fuzzing.txt -v
nuclei -l /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -t /root/nuclei-templates/ -c 50 -o /root/recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt/root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -o /root/recon/$domain/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -o /root/recon/$domain/scan/jaeles/ -v
done
}
vuln_scanner

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  |  gauplus -t 30 | tee -a /root/recon/$domain/url/gaplus-urls.txt
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | hakrawler | tee -a /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt  | katana -o /root/recon/$domain/url/katana.txt
#cat /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt
paramspider -l /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt -s
cat /root/OK-VPS/tools/ParamSpider/results/*.txt > /root/OK-VPS/tools/ParamSpider/results/ParamSpider_all.txt && cp -r /root/OK-VPS/tools/ParamSpider/results/ParamSpider_all.txt /root/recon/$domain/url 
cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/fainal/best/all_active_sub.txt 
cat /root/recon/$domain/url/*.txt > /root/recon/$domain/url/all-url.txt
cat /root/recon/$domain/url/all-url.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/sort-url.txt
httpx -l /root/recon/$domain/url/sort-url.txt -o /root/recon/$domain/url/url_httpx.txt
arjun -i /root/recon/$domain/url/url_httpx.txt -t 20 -oT /root/recon/$domain/url/arjun.txt
cat /root/recon/$domain/url/*.txt | tee -a /root/recon/$domain/url/2all-url.txt
cat /root/recon/$domain/url/2all-url.txt | sort --unique | tee /root/recon/$domain/url/final-url.txt
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
gf my-lfi /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/my-Redirect.txt
gf aws-keys /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/aws-keys-json.txt
gf interestingsubs /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  |  tee /root/recon/$domain/gf/interestingsubs.txt
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
done
}
Refactors_xss

Open_Redirect(){
for domain in $(cat $host);
do
python3  /root/OK-VPS/tools/Oralyzer/oralyzer.py -l /root/recon/$domain/url/valid_urls.txt | tee -a /root/recon/$domain/scan/redirect.txt
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/fuzzing-templates/redirect/open-redirect.yaml -c 60  -o /root/recon/$domain/scan/nuclei/urls_redirect.txt -v
done
}
Open_Redirect

dir-traversal(){
for domain in $(cat $host);
do
sed 's/=.*$/=/' /root/recon/$domain/gf/my_lfi.txt | anew | tee -a /root/recon/$domain/gf/rady_lfi.txt
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/dir-traversal.yaml -c 60  -o /root/recon/$domain/scan/nuclei/dir-traversal.txt -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header -v
jaeles scan -c 50 -s /root/templates/best/lfi-header-windows-01.yaml -U /root/recon/$domain/url/valid_urls.txt -o /root/recon/$domain/scan/my-jaeles/lfi-header-windows -v
done
}
dir-traversal

Bilnd_xss(){
for domain in $(cat $host);
do
nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100  -o /root/recon/$domain/xss/header_blind_xss.txt -v
done
}
Bilnd_xss


Get_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/getjs_urls.txt
cat /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/Domain_js_urls.txt
cat /root/recon/$domain/js_url/*.txt > /root/recon/$domain/js_url/all_js_url.txt
cat /root/recon/$domain/js_url/all_js_url.txt | sort --unique | tee /root/recon/$domain/js_url/fina_js_url.txt
cat /root/recon/$domain/js_url/fina_js_url.txt | httpx -threads 150 -o /root/recon/$domain/js_url/jshttpxurl.txt
cat /root/recon/$domain/js_url/jshttpxurl.txt | sort --unique | tee /root/recon/$domain/js_url/good_js_url.txt
#relative-url-extractor https://github.com/jobertabma/relative-url-extractor
#LinkFinder https://github.com/GerbenJavado/LinkFinder
done
}
Get_js

Dom_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/js_url/good_js_url.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh | tee -a /root/recon/$domain/xss/Dom_xss.txt
done
}
Dom_xss

SecretFinder_js(){
for url in $(cat /root/recon/$domain/js_url/good_js_url.txt);
do
python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i $url -o cli | tee -a /root/recon/$domain/js_url/js_SecretFinder.txt; done
done
}
SecretFinder_js

Fuzz_Endpoint(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  -w /root/recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/recon/$domain/dri/Endpoint_Dir.txt
done
}
Fuzz_Endpoint

FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | tee -a /root/recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active

ip_sub(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/fainal/active_subdomain.txt  | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/subdomain_ip.txt
dirsearch -l /root/recon/$domain/subdomain/good/subdomain_ip.txt | tee -a /root/recon/$domain/dri/sub_ip_dri_activ.txt
done
}
ip_sub

