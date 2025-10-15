# VirusTotal Hash Checker

A Python script to query VirusTotal for multiple file hashes (MD5, SHA1, SHA256) from an Excel file and save the results to a CSV file. The script handles resuming from the last processed hash, avoids duplicates, and respects API request limits.

---

## Features

- Reads hashes from Excel files
- Queries VirusTotal API for hash analysis
- Handles MD5, SHA1, and SHA256
- Avoids duplicate entries in output CSV
- Can resume processing from where it left off
- Stops automatically after a daily API limit

---

## Requirements

- Python 3.8+
- Packages listed in `requirements.txt`

---

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/virustotal-hash-checker.git
   cd virustotal-hash-checker

## Install dependencies:

pip install -r requirements.txt


## Create a .env file in the root folder:

VT_API_KEY=your_virustotal_api_key_here


Prepare your input Excel file with hashes in the first three columns (MD5, SHA1, SHA256).

## Usage

Run the script:

python hashes.py


You will be prompted to provide:

Input Excel file path

Output CSV file path

The script will process hashes, query VirusTotal, and save results to the CSV.

Output

The CSV will contain:

MD5	MalScore	Creation Time	Last Submission

MalScore shows the number of malicious detections along with the total checked.

Duplicate hashes are automatically removed.

## Notes

Respect VirusTotal API rate limits (default: 500 queries per run).

Do not commit your .env file with your API key to GitHub.

You can modify daily_limit in the script to control the number of requests per run.

License

MIT License