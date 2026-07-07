# Phishing URL Detector

Phishing URL Detector is a Python-based web application that checks URLs for common phishing indicators. It calculates a risk score and classifies each URL as SAFE, SUSPICIOUS, or PHISHING.

## Problem Statement

Many phishing websites look similar to legitimate websites, making them difficult to identify. This project helps users detect suspicious URLs before visiting them.

## Objective

The main objectives of this project are:

- Detect phishing URLs using rule-based analysis
- Calculate a risk score for each URL
- Display the analysis through a simple web interface
- Provide API support for URL checking

## Features

- Rule-based phishing URL detection
- 12 security checks
- Risk score calculation
- SAFE / SUSPICIOUS / PHISHING verdict
- Flask-based web interface
- REST API support
- Unit testing using Pytest

## Technologies Used

- Python
- Flask
- HTML
- CSS
- Pytest

## Project Structure

```text
phishing-url-detector/
│── app.py
│── detector.py
│── requirements.txt
│── README.md
│── templates/
│     └── index.html
│── tests/
│     └── test_detector.py
```

## How to Run

1. Clone this repository
2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Run the application

```bash
python app.py
```

4. Open your browser and visit

```
http://127.0.0.1:5000
```

## Usage

### Web Interface

Paste any URL into the input box and click **Analyze**.

### Command Line

```bash
python detector.py "http://instagram.com.verify-account.xyz/login"
```

### REST API

```bash
curl -X POST http://127.0.0.1:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"url":"http://instagram.com.verify-account.xyz/login"}'
```

### Run Tests

```bash
python -m pytest tests/ -v
```

## Workflow

- Enter a URL
- Click Analyze
- System checks the URL
- Risk score is calculated
- Final verdict is displayed

## How It Works

The application checks a URL using multiple security rules. Every rule that is triggered adds a specific risk score. Based on the final score, the URL is classified as:

| Score | Verdict |
|-------:|---------|
| 0 – 19 | SAFE |
| 20 – 49 | SUSPICIOUS |
| 50+ | PHISHING |

The application also displays the triggered rules along with the risk score, making it easy to understand why a URL was marked as suspicious or phishing.

## Advantages

- Easy to use
- Fast URL analysis
- Rule-based detection
- Lightweight application

## Limitations

- Rule-based detection only
- Does not use Machine Learning
- Does not verify URLs online
- Accuracy depends on predefined detection rules
  
## Future Improvements

- Browser Extension
- Detection History
- Machine Learning integration
- Google Safe Browsing API
  
## Author

**Mohit Jagudi**

- GitHub: [Mohit Jagudi](https://github.com/Mohit-Jagudi/)
- LinkedIn: [Mohit Jagudi](https://www.linkedin.com/in/mohit-jagudi/)
