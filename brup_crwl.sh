  GNU nano 4.9                                                              1.sh
#!/bin/bash

# Set the Burp proxy address and port
proxy="http://127.0.0.1:8080"
url="/home/mobaxterm/urls.txt"
# Loop over the URLs in the urls.txt file and send each URL through the Burp proxy using Curl
while read url; do
    curl -x "$proxy" -k "$url"
done < urls.txt
