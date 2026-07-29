from fastapi import FastAPI
from pydantic import BaseModel
import os
import socket
import ipaddress
import requests
from urllib.parse import urlparse


app = FastAPI()


SANDBOX = "/srv/agent-redteam/sandbox-450e215936"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class Request(BaseModel):
    tool: str
    arguments: dict



# -------------------------
# FILE SECURITY
# -------------------------

def safe_file(path):

    real_path = os.path.realpath(path)

    sandbox_real = os.path.realpath(SANDBOX)

    if not real_path.startswith(sandbox_real + os.sep):
        return False

    return True



def read_file(path):

    with open(path,"r") as f:
        return f.read()



# -------------------------
# URL SECURITY
# -------------------------

def safe_url(url):

    try:
        parsed = urlparse(url)

        host = parsed.hostname

        if not host:
            return False


        # Only allow exact hosts
        if host not in ALLOWED_HOSTS:
            return False


        # Resolve DNS

        ips = socket.gethostbyname_ex(host)[2]


        for ip in ips:

            addr = ipaddress.ip_address(ip)


            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
            ):
                return False


        return True


    except Exception:
        return False



def fetch_url(url):

    r = requests.get(
        url,
        timeout=5,
        allow_redirects=False
    )

    return r.text



# -------------------------
# MAIN GUARDRAIL
# -------------------------

@app.post("/check")
def guardrail(req:Request):


    if req.tool=="read_file":

        path=req.arguments.get("path")


        if safe_file(path):

            return {
                "action":"allow",
                "reason":"Inside sandbox",
                "result":read_file(path)
            }

        else:

            return {
                "action":"block",
                "reason":"Path outside sandbox"
            }



    elif req.tool=="fetch_url":

        url=req.arguments.get("url")


        if safe_url(url):

            return {
                "action":"allow",
                "reason":"Allowed host",
                "result":fetch_url(url)
            }


        else:

            return {
                "action":"block",
                "reason":"Unsafe URL"
            }



    return {
        "action":"block",
        "reason":"Unknown tool"
    }