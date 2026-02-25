import json
import os
from urllib.parse import urlparse

def parse_har(file_path):

    ignore_ext = {"jpg", "jpeg", "png", "gif", "css", "js", "svg", "mp4", "mp3"}
    vectors = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)

        entries = har_data['log']['entries']
        if not entries:
            print("[!] HAR file empty")
            return []

        first_url = entries[0]['request']['url']
        targetname = urlparse(first_url).netloc
        os.makedirs("results", exist_ok=True)
        output_file = f"results/{targetname}_scanner.json"

        for entry in entries:
            req = entry['request']
            url = req['url']

            path = urlparse(url).path
            ext = path.split('.')[-1].lower()
            if ext in ignore_ext:
                continue

            for param in req.get('queryString', []):
                vectors.append({
                    "url": url,
                    "method": req['method'],
                    "location": "url_param",
                    "name": param['name'],
                    "value": param['value']
                })

            for cookie in req.get('cookies', []):
                vectors.append({
                    "url": url,
                    "method": req['method'],
                    "location": "cookie",
                    "name": cookie['name'],
                    "value": cookie['value']
                })

            for header in req.get('headers', []):
                vectors.append({
                    "url": url,
                    "method": req['method'],
                    "location": "header",
                    "name": header['name'],
                    "value": header['value']
                })

            post_data = req.get('postData', {})

            if 'params' in post_data:
                for p in post_data['params']:
                    vectors.append({
                        "url": url,
                        "method": req['method'],
                        "location": "form_body",
                        "name": p['name'],
                        "value": p['value']
                    })

            elif 'text' in post_data:
                vectors.append({
                    "url": url,
                    "method": req['method'],
                    "location": "raw_body",
                    "name": "payload",
                    "value": post_data['text']
                })

        print(f"[+] Passive Scan: Extracted {len(vectors)} vectors from HAR")

        return output_json(vectors, targetname, output_file)

    except Exception as e:
        print(f"[!] HAR Parsing failed: {e} or file/path/directory is not found")
        return []
    
def output_json(vectors, target_name, output_file):
    results = {
        "target": target_name,
        "scan_type": "hybrid",
        "vector_count": len(vectors),
        "vectors": vectors
    }
    with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
                print(f"[+] Output saved to {output_file}")
    return results
    