#!/bin/bash
# grab new versions of the scripts, sanitize, then add to git
#printf "examples:\npapermill initial-scans.ipynb /dev/stdout -p input_data feemcotech.solutions\npapermill libvirt-provision.ipynb /dev/stdout -p hostname ubuntu -p domainname private -p url https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -p os_variant ubuntu-stable-latest -p size 80G -p ram 4096\n"
jupyter nbconvert --clear-output --to notebook --output=/share/public-git-repos/automation-tools/initial-scans.ipynb /share/pentests/ansible-pentest/initial\ scans.ipynb >/dev/null
jupyter nbconvert --clear-output --to notebook --output=/share/public-git-repos/automation-tools/libvirt-provision.ipynb /share/pentests/ansible-pentest/libvirt-provision.ipynb >/dev/null
