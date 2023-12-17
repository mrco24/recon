#!/bin/bash

host=$1


for sub in $(cat $host);
do
    subfinder -d $sub -all -silent | anew  passive_recursive.txt
    assetfinder --subs-only $sub | anew  passive_recursive.txt
    amass enum -passive -d $sub | anew  passive_recursive.txt
    findomain --quiet -t $sub | anew passive_recursive.txt
    cat *.txt > R_allsub.txt
    cat R_allsub.txt | anew Recursive_finalsub_all.txt

done

