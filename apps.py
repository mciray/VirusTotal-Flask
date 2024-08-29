from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
# api keyiniz.

def extract_urls(page_url):
    try:
        response = requests.get(page_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # gelen url deki bütün href'leri bul
        urls = [a['href'] for a in soup.find_all('a', href=True)]
        return urls
    except requests.exceptions.RequestException as e:
        print(f"Hata: {e}")
        return []

def check_url_safety(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {
        'url': url
    }
    try:
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
            if analysis_response.status_code == 200:
                result_data = analysis_response.json()
                stats = result_data['data']['attributes']['stats']
                malicious_count = stats['malicious']
                return {
                    "url": url,
                    "malicious": malicious_count > 0,
                    "details": stats
                }
            else:
                return {
                    "url": url,
                    "malicious": None,
                    "details": "Analysis failed"
                }
        else:
            return {
                "url": url,
                "malicious": None,
                "details": "URL submission failed"
            }
    except requests.exceptions.RequestException as e:
        print(f"Hata: {e}")
        return {
            "url": url,
            "malicious": None,
            "details": "Request exception"
        }

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        page_url = request.form.get('page_url')
        # formdan gelen url içindeki bütün url leri bulması için fonksiyona yolla 
        urls = extract_urls(page_url)
        # tarama sonuçlarını tut.
        scan_results = []
        for url in urls:
            # tarama sonuçlarından gelen url leri kontrol et her birini virustotal e yolla.
            result = check_url_safety(url)
            # resultu göstermek için listeye yolla ve onu en son sayfama context olarak yolla.
            scan_results.append(result)
            print(f"URL: {result['url']}, Zararlı: {result['malicious']}, Detaylar: {result['details']}")
        return render_template('success.html', scan_results=scan_results)
    return render_template('index.html')