#!/bin/bash

URL=$1
directoryname=$2
HTTPXCALL="httpx -silent -no-color -random-agent"
output_path="output/$directoryname"

mkdir -p "output" && mkdir -p $output_path

# Use waybackurls, SonarSearch/crobat, and gau to gather URLs
echo "Gathering URLs..."
waybackurls $URL > $output_path/waybackurls.txt
#crobat -s $URL > $output_path/crobat.txt
gau $URL > $output_path/gau.txt
amass enum -d $URL -silent | sort -u > $output_path/amass.txt


# Use paramspider to gather parameters
echo "Gathering parameters..."
paramspider -s --domain $URL > $output_path/paramspider.txt


echo "Checking URL status..."
cat $output_path/amass.txt | $HTTPXCALL --status-code | grep "200" | sed 's/\[200\]//g' > $output_path/amass_status.txt
cat $output_path/waybackurls.txt | sort -u | $HTTPXCALL --status-code | grep "200" | sed 's/\[200\]//g' > $output_path/waybackurls_status.txt
#cat $output_path/crobat.txt | $HTTPXCALL --status-code | grep "200" > $output_path/crobat_status.txt
cat $output_path/gau.txt | sort -u | $HTTPXCALL --status-code | grep "200" | sed 's/\[200\]//g' > $output_path/gau_status.txt

# unique urls
status_files=("amass_status.txt" "waybackurls_status.txt" "gau_status.txt")
for file in "${status_files[@]}"; do
  cat "$output_path/$file" >> $output_path/results.txt
done
sort -u $output_path/results.txt -o $output_path/results.txt


# Use ffuf to fuzz the gathered parameters
# echo "Fuzzing parameters..."
# ffuf -w paramspider.txt -u $URL/FUZZ -v > ffuf.txt