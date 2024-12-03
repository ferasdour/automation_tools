# automation repository
Working on creating an automation setup that will allow me to further my pentesting capabilities at scale on individual levels. All of these should be considered alpha. That's also why I'm currently just doing automated pushes, because it's something I'm working on and want to show that its a thing, but early stages.

Current Files:
- initial-scans.ipynb: Recon jupyter script I created for starting initial scans on htb, been adjusting it as new things come in.
-- Idea is that you can run papermill, or open it manually. Papermill will run the scan and provide setout output and relevant files created. Running manually will do the startup, then provide a working environment for the rest of your pentest.
-- recently added some copy paste things for "as needed" basis, when running in jupyter august 2024
- libvirt-provision.ipynb: a simple provisioning notebook designed for use with libvirt and papermill.
- provision.sh: an example script that replaces the ssh public key that gets put into authorized_keys, with one from your home directory, then provisions a basic ubuntu system
- sanitize.sh: this is what I'm using to take my development area scripts and add them to my local repository area.
- trufflehog-org.sh: just something that's come in handy a few times, for bug hunting, being able to spin up a trufflehog scan using docker, results (in a few formats) saved to /tmp/
- k3d-provision.yml: using the libvirt provisioning tool, papermill, and ansible, making a way to create multi-vm/multi-node k3s deployment.
-- example: ansible-playbook -i localhost, k3d-provision.yml -u ansible -T 90 --ask-become-pass

