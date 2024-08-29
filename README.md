
# URL Security Scanning Application

This project is a Flask application that scans all URLs on a given webpage and checks their safety using the VirusTotal API.

## Features

- Automatically extracts all links from a webpage.
- Checks the security status of each URL using the VirusTotal API.
- Displays the results to the user.

## Requirements

- Docker

## Installation

### 1. Clone the Repository

First, clone this project to your local machine:

```bash
git clone https://github.com/mciray/VirusTotal-Flask.git
```

### 2. Build and Start the Application with Docker

To build the Docker image and start the container:

```bash
docker-compose up --build
```

### 3. Create `.env` File

```bash
VIRUSTOTAL_API_KEY = <Write your Api Key>
```

### Application Running

You can view the application by navigating to:

```bash
http://localhost:5000
```
