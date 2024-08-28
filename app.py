from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def extract_urls(page_url):
    try:
        response = requests.get(page_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        urls = [a['href'] for a in soup.find_all('a', href=True)]
        return urls
    except requests.exceptions.RequestException as e:
        return []

def check_url_safety(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {
        'url': url
    }
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
        if analysis_response.status_code == 200:
            return True
        else:
            return False
    else:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        page_url = request.form.get('page_url')
        urls = extract_urls(page_url)
        scan_results = {}
        for url in urls:
            scan_results[url] = check_url_safety(url)
            print(scan_results)
        return render_template('success.html', scan_results=scan_results)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
