import json as json_lib
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler, HTTPSHandler, HTTPCookieProcessor
from collections import namedtuple
from http.cookiejar import CookieJar


Response = namedtuple('Response', 'request content json status url headers cookiejar')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, params={}, json=None, data=None, headers={}, method='GET', verify=True, redirect=True, cookiejar=None):
    """
    s
    Makes a HTTP requests using urllib and returns a namedtuple with the following properties:
        - request
        - content
        - json (dict; or None)
        - headers (dict; all lowercase keys)
            - https://stackoverflow.com/questions/5258977/are-http-headers-case-sensitive
        - status
        - url (final url, after any redirects)
        - cookiejar
    """
    method = method.upper()
    headers = { k.lower(): v for k, v in headers.items() }  # lowecase headers

    if params: url += '?' + urlencode(params)  # build URL from params
    if json and data: raise Exception('Cannot provide both json and data parameters')
    if method not in ['POST', 'PATCH', 'PUT'] and (json or data): raise Exception('Request method must POST, PATCH or PUT if json or data is provided')

    if json:  # if we have json, stringify and put it in our data variable
        headers['content-type'] = 'application/json'
        data = json_lib.dumps(json).encode('utf-8')
    elif data:
        data = urlencode(data).encode()

    if not cookiejar:
        cookiejar = CookieJar()

    ctx = ssl.create_default_context()
    if not verify:  # ignore ssl errors
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers = []
    handlers.append(HTTPSHandler(context=ctx))
    handlers.append(HTTPCookieProcessor(cookiejar=cookiejar))

    if not redirect:
        no_redirect = NoRedirect()
        handlers.append(no_redirect)

    opener = build_opener(*handlers)
    req = Request(url, data=data, headers=headers, method=method)

    try:
        with opener.open(req) as resp:
            status, content, resp_url = (resp.getcode(), resp.read(), resp.geturl())
            headers = {k.lower(): v for k, v in list(resp.info().items())}
            json = json_lib.loads(content) if 'application/json' in headers.get('content-type', '').lower() else None
    except HTTPError as e:
        status, content, resp_url = (e.code, e.read(), e.geturl())
        headers = {k.lower(): v for k, v in list(e.headers.items())}
        json = json_lib.loads(content) if 'application/json' in headers.get('content-type', '').lower() else None

    return Response(req, content, json, status, resp_url, headers, cookiejar)


URLS = [
    ('https://raw.githubusercontent.com/pyca/cryptography/master/CHANGELOG.rst', 'DELTA_CRYPTOGRAPHY'),
    ('https://puffingbillyrunningfestival.com.au', 'DELTA_PBR')
]

import os
from hashlib import sha256

if __name__ == "__main__":
    for url, delta_var in URLS:
        response = request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:82.0) Gecko/20100101 Firefox/82.0"})
        hash = sha256(response.content[:2500]).hexdigest()

        delta_url = os.environ.get(delta_var)
        if delta_url:
            request(delta_url, method='POST', json={'value': hash})
        else:
            print(f"Missing environment variable: {delta_var}")

