#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

#Special_subdomain(){
#for domain in $(cat $host);
#do
#cat /root/recon/$domain/subdomain/good/Gen_sub/active_subdomain.txt | anew /root/recon/$domain/Special_subdomain/Special_subdomain.txt 
#done
#}
#Special_subdomain

Special_subdomain_scanner(){
for domain in $(cat $host);
do
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/cves/  -o /root/scan/my-cves.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/vulnerabilities/  -o /root/scan/my-vulnerabilities.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/technologies/  -o /root/scan/my-technologies.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/ -o /root/scan/My-Nuclei-Templates.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/Nuclei 1/ -o /root/scan/my-Nuclei.txt -v
cat /root/sub.txt | nuclei -t  nuclei -t /root/templates/my-nuclei-templates/workflows/ -o /root/scan/my-workflows.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/helpers/ -o /root/scan/my-helpers.txt -v
cat /root/sub.txt | nuclei -t /root/templates/my-nuclei-templates/idscan/ -o /root/scan/my-idscan.txt -v
cat /root/sub.txt | nuclei -t /root/templates/nuclei-templates/cves/ -o /root/scan/new/cve.txt -v
cat /root/sub.txt | nuclei -t /root/templates/nuclei-templates/vulnerabilities/  -o /root/scan/new/vulnerabilities.txt -v
cat /root/sub.txt | nuclei -t /root/templates/nuclei-templates/takeovers/ -o /root/scan/new/takover.txt -v
cat /root/sub.txt | nuclei -t /root/templates/nuclei-templates/technologies/ -o /root/scan/new/technologies.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/sub.txt -o /root/scan/my-jaeles/ -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/sub.txt -o /root/scan/jaeles/ -v
done
}
Special_subdomain_scanner

Url_endpoints(){
for domain in $(cat $host);
do
cat cat /root/sub.txt | cut -d "/" -f4- >> /root/scan/Dri/url_endpoints.txt
done
}
Url_endpoints

Fuzz_Endpoint(){
for domain in $(cat $host);
do
dirsearch -l cat /root/sub.txt -w /root/scan/Dri/url_endpoints.txt -i 200,301,302 | tee -a /root/scan/Dri/Endpoint_Dir.txt
done
}
Fuzz_Endpoint

Special_subdomain_Dir(){
for domain in $(cat $host);
do
dirsearch -l /root/sub.txt | tee -a /root/scan/Dri/domain_Dri.txt
done
}
Special_subdomain_Dir

Special_subdomain_Dir2(){
for domain in $(cat $host);
do
dirsearch -l target.txt -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sqlasp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip -i 200 | tee -a /root/scan/Dri/specail_dri.txt
done
}
Special_subdomain_Dir2
