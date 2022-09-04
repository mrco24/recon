#!/bin/bash

host=$1

urls(){
for sub in $(cat $host);
do
curl "https://web.archive.org/cdx/search/cdx?url=$sub/*&output=text&fl=original&collapse=urlkey" | grep "=" | tee urls.txt
done
}
urls
