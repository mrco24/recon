#!/bin/bash

host=$1
wordlist="/root/wordlist/all.txt"
resolver="/root/wordlist/resolvers.txt"

Special_subdomain(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/Gen_sub/active_subdomain.txt | anew /root/recon/$domain/Special_subdomain/Special_subdomain.txt 
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
