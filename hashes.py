import requests
import pandas as pd
import time
import os


# ✅ VirusTotal API Key
API_KEY="YOUR_VIRUSTOTAL_API_KEY"
input_file = r"C:\Users\HP\Desktop\hashes\22-09-2025hashes.xlsx"
output_file =r"C:\Users\HP\Desktop\hashes\1stbatch_22_09_2025.csv"

# Load all hashes from Excel
df = pd.read_excel(input_file)
hash_list = df.iloc[:, [0, 1, 2]].values.tolist()

# Load processed hashes from output CSV if exists
if os.path.exists(output_file):
    existing_df = pd.read_csv(output_file)
    existing_df = existing_df.drop_duplicates(subset='MD5')
    existing_df.to_csv(output_file, index=False)  # Clean duplicates on disk
    processed_hashes = set(existing_df['MD5'].dropna())
else:
    processed_hashes = set()

# Find last processed index in Excel list to resume
last_processed_index = -1
for idx, (md5, sha1, sha256) in enumerate(hash_list):
    if md5 in processed_hashes:
        last_processed_index = idx

start_index = last_processed_index + 1
print(f"Resuming from index {start_index} of {len(hash_list)} total hashes")

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def get_virustotal_data(md5, sha1=None, sha256=None):
    headers = {"x-apikey": API_KEY}
    for hash_val in [md5, sha1, sha256]:
        if not hash_val or pd.isna(hash_val):
            continue
        response = requests.get(VT_URL.format(hash_val), headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            mal_score = stats['malicious']
            undetected = stats['undetected']
            overall_score = mal_score + undetected

            creation_time = data['data']['attributes'].get('creation_date', 'N/A')
            last_submission = data['data']['attributes'].get('last_submission_date', 'N/A')

            if creation_time != 'N/A':
                creation_time = time.strftime('%Y-%m-%d', time.gmtime(creation_time))
            if last_submission != 'N/A':
                last_submission = time.strftime('%Y-%m-%d', time.gmtime(last_submission))

            return [hash_val, f"{mal_score}({overall_score})", creation_time, last_submission]
    print(f"No data found for: {md5}")
    return [md5, 'Error', 'Error', 'Error']

results = []
processed_count = 0

for i in range(start_index, len(hash_list)):
    md5, sha1, sha256 = hash_list[i]

    # Just an extra safety check, should be redundant:
    if md5 in processed_hashes:
        continue

    print(f"Processing {md5} ({i+1}/{len(hash_list)})")
    result = get_virustotal_data(md5, sha1, sha256)
    results.append(result)
    processed_hashes.add(md5)
    processed_count += 1

    if len(results) >= 10:
        temp_df = pd.DataFrame(results, columns=['MD5', 'MalScore', 'Creation Time', 'Last Submission'])
        if os.path.exists(output_file):
            combined = pd.concat([pd.read_csv(output_file), temp_df]).drop_duplicates(subset='MD5')
        else:
            combined = temp_df
        combined.to_csv(output_file, index=False)
        results.clear()

    if processed_count >= 500:
        print("Reached daily limit (500 requests). Stopping.")
        break

if results:
    temp_df = pd.DataFrame(results, columns=['MD5', 'MalScore', 'Creation Time', 'Last Submission'])
    if os.path.exists(output_file):
        combined = pd.concat([pd.read_csv(output_file), temp_df]).drop_duplicates(subset='MD5')
    else:
        combined = temp_df
    combined.to_csv(output_file, index=False)

print(f"✅ All done! Results saved to: {output_file}") 
