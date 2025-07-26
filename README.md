# Phishing Website Detection Tool

A lightweight Python tool that helps users detect potentially harmful phishing URLs using machine learning techniques.

## Overview

Phishing websites trick users into entering personal data, leading to identity theft and fraud. This tool analyzes URLs to determine if they are potentially malicious by examining various features and patterns commonly found in phishing websites.

## Features

- URL feature extraction (length, IP address usage, suspicious symbols, etc.)
- Machine learning-based classification using Random Forest algorithm
- Simple web interface for easy URL checking
- Dataset generation tool for testing and training
- Model training and evaluation capabilities

## Project Structure

This project has been reorganized into a flat structure for easier hosting:

```
/
├── app.py                  # Flask web application
├── index.html              # Main HTML page
├── phishing_detector.py    # Core detection functionality
├── phishing_detector_cli.py # Command-line interface
├── generate_dataset.py     # Dataset generation tool
├── requirements.txt        # Python dependencies
├── css/                    # CSS stylesheets
│   └── style.css
├── js/                     # JavaScript files
│   └── script.js
└── images/                 # Image assets
    ├── phishing.svg
    └── shield.svg
```

## Requirements

- Python 3.6+
- Required packages (install via `pip install -r requirements.txt`):
  - pandas
  - numpy
  - scikit-learn
  - joblib
  - flask

## Installation

1. Clone or download this repository
2. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Web Interface

To start the web application:

```bash
python app.py
```

Then open your browser and navigate to `http://localhost:5000`

### Command Line Interface

The tool also provides a command-line interface for various operations:

#### Generating a Dataset

```bash
python phishing_detector_cli.py generate --samples 2000 --ratio 0.5 --output phishing_dataset.csv
```

#### Training the Model

```bash
python phishing_detector_cli.py train --dataset phishing_dataset.csv
```

#### Checking a URL

```bash
python phishing_detector_cli.py check --url example.com --verbose
```

#### Batch Processing URLs

```bash
python phishing_detector_cli.py batch --input urls.txt --output results.csv
```

## How It Works

The phishing detector extracts various features from URLs, including:

1. URL length
2. Presence of IP addresses
3. Use of @ symbols
4. Presence of double slashes in the path
5. Dashes in domain names
6. Multiple subdomains
7. HTTPS usage
8. Domain registration length
9. Suspicious words
10. URL shortening services

These features are fed into a Random Forest classifier that has been trained on a dataset of legitimate and phishing URLs. The model then predicts whether a given URL is likely to be phishing or legitimate, along with a confidence score.

## License

This project is open source and available for educational and personal use.

## Author

Created by Aayush