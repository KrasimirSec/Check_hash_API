import hashlib
import requests
import sys

def calculate_hash(file_path, hash_type='sha256'):
    hasher = hashlib.new(hash_type)
    with open(file_path, 'rb') as file:
        buf = file.read(65536)
        while buf:
            hasher.update(buf)
            buf = file.read(65536)
    return hasher.hexdigest()

def get_virustotal_report(hash_value, api_key):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': api_key,
        'resource': hash_value
    }
    headers = {
        'Accept': 'application/json'
    }
    
    response = requests.get(url, params=params, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            return result['permalink']
        else:
            return "No report found for this hash."
    else:
        return f"Error: {response.status_code}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Please enter the path to the file you want to hash: ")
    
    file_hash = calculate_hash(file_path)
    print(f"Calculated hash: {file_hash}")

    api_key = input("Please enter your VirusTotal API key: ")
    report_link = get_virustotal_report(file_hash, api_key)
    print(f"VirusTotal report link: {report_link}")
