# URL Güvenlik Tarama Uygulaması

Bu proje, verilen bir web sayfasındaki tüm URL'leri tarayan ve VirusTotal API'sini kullanarak bu URL'lerin güvenli olup olmadığını kontrol eden bir Flask uygulamasıdır.

## Özellikler

- Web sayfasındaki tüm bağlantıları otomatik olarak çıkarır.
- VirusTotal API'si ile her URL'nin güvenlik durumunu kontrol eder.
- Sonuçları kullanıcıya gösterir.

## Gereksinimler

- Docker

## Kurulum

### 1. Depoyu Klonlayın

Öncelikle, bu projeyi yerel makinenize klonlayın:

```bash
git clone https://github.com/mciray/VirusTotal-Flask.git

```
### 2. Docker ile uygulamayı build yapıp başlatın

Docker imajını oluşturup konteyneri başlatmak için:

```bash
docker-compose up --build

```

### Uygulama ayakta

Bu adrese giderek uygulamayı görebilirsiniz.

```bash
http://localhost:5000

```

