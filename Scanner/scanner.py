import requests
import json
from urllib.parse import urlparse, parse_qs
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_url(url, scope=None, output_file=None, session_cookie=None):

    session = requests.Session()

    headers = {
        "User-Agent": "EthicalQuoc/2026.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    if session_cookie:
        domain = urlparse(url).hostname
        session.cookies.set("session", session_cookie, domain=domain)

    print(f"[*] Scanning target: {url}")
    vectors = []

    try:
        response = session.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

    print(f"[+] Status code: {response.status_code}")
    if scope is None or scope == "cookies":
        cookies_dict = session.cookies.get_dict()
        for name, value in cookies_dict.items():
            vectors.append({"location": "cookie","name": name,"value": value})

        for header, value in response.headers.items():
            if header.lower() == "set-cookie":
                cookie_raw = value.split(';')[0]
                if '=' in cookie_raw:
                    c_name, c_value = cookie_raw.split('=', 1)
                    if not any(v['name'] == c_name.strip() for v in vectors):
                        vectors.append({ "location": "cookie_header","name": c_name.strip(),"value": c_value.strip()})

    if scope is None or scope == "params":
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            for v in values:
                vectors.append({"location": "param","name": param,"value": v})

    if scope is None or scope == "headers":
        interesting_headers = ['Content-Type', 'User-Agent', 'Referer', 'X-Custom-Header']
        for h in interesting_headers:
            if h in response.headers:
                vectors.append({"location": "header","name": h,"value": response.headers[h]})

    if scope is None or scope == "body":
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                json_body = response.json()
                if isinstance(json_body, dict):
                    for key, value in json_body.items():
                        vectors.append({"location": "body","name": key,"value": str(value)})
            except:
                pass
        else:
            vectors.append({"location": "body","name": "raw_body","value": response.text[:1000]})

    result = {
        "target": url,
        "status_code": response.status_code,
        "vector_count": len(vectors),
        "vectors": vectors
    }

    print(f"[+] Collected {len(vectors)} input vectors")

    for v in vectors:
        if "cookie" in v['location']:
            print(f"    [!] Found Cookie -> {v['name']}: {v['value'][:50]}...")

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=4, ensure_ascii=False)
            print(f"[+] Output saved to {output_file}")
        except Exception as e:
            print(f"[!] Failed to save output: {e}")

    return result