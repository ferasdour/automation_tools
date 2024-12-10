#!/bin/bash
echo "copy ssh key to provision script"
sed -i s/${grep -i ssh-rsa libvirt-provision.ipynb |awk '{print $3,$4}'|sed s/'\\n",'//g}/${grep -i ssh -m 1 ~/.ssh/id_*.pub}/g libvirt-provision.ipynb 
papermill libvirt-provision.ipynb /dev/stdout -p hostname ubuntu -p domainname private -p url https://cloud-images.ubuntu.com/releases/24.10/release/ubuntu-24.10-server-cloudimg-amd64.img -p os_variant ubuntu-stable-latest -p size 40G -p ram 2048
