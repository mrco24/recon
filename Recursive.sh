#!/bin/bash

host=$1

Recursive(){
for sub in $(cat $host);
do
    subfinder -d $sub -all -silent | anew -q passive_recursive.txt
    assetfinder --subs-only $sub | anew -q passive_recursive.txt
    amass enum -passive -d $sub | anew -q passive_recursive.txt
    findomain --quiet -t $sub | anew -q assive_recursive.txt
    cat *.txt > R_allsub.txt
    cat R_allsub.txt | anew -q Recursive_finalsub_all.txt

done
}
Recursive
