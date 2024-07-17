#!/bin/bash
read -p "Enter github orgname: " org
echo "running trufflehog against $org"
docker run --rm -it --log-driver=none -a stdin -a stdout -a stderr trufflesecurity/trufflehog:latest github --org=$org --issue-comments --pr-comments 2>&1 >> /tmp/tmp-trufflehog
echo "Trufflehog complete, lets try to see if we can grab username/password lists from the results"
echo "-- combolist --"
grep -i "Raw result:" /tmp/tmp-trufflehog |grep "\@"| sed s/":\/\/"/" "/g|awk -F "@" '{print $1}'|awk '{print $4}'|sort -u > /tmp/tmp-trufflehog-userpass
echo "-- user list --"
grep -i "Raw result:" /tmp/tmp-trufflehog |grep "\@"| sed s/":\/\/"/" "/g|awk -F "@" '{print $1}'|awk '{print $4}'|awk -F ":" '{print $1}' |sort -u > /tmp/tmp-trufflehog-user
echo "-- pass list --"
grep -i "Raw result:" /tmp/tmp-trufflehog |grep "\@"| sed s/":\/\/"/" "/g|awk -F "@" '{print $1}'|awk '{print $4}'|awk -F ":" '{print $2}' |sort -u > /tmp/tmp-trufflehog-pass
echo "collecting ssh-key url list"
grep -i "raw result:\|link:" /tmp/tmp-trufflehog |grep -i "ssh private key" -A1|grep -i "link:" |awk '{print $2}' > /tmp/tmp-trufflehog-keys
echo "other detections to check out"
grep -i "Detector Type:" /tmp/tmp-trufflehog |sort -u > /tmp/tmp-trufflehog-detections