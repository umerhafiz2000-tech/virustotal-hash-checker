import requests
import pandas as pd
import time
import os


#API_KEY="0daad9cc595099ee70a09c08e4692b05a9b44a87c0d2d2d0a4b56db31f4b5432"
API_KEY = "9af7109f990ad1f180632cbbd708d93655fea6d08d3d45c1ffe48e0eba5d46bf"
#api key for account testhashes5@gmail.com onn 6/25/2025
#API_KEY = "1100a82fdd3a6cb4f45bc09cb7bba368949dca7355cccc81dd17dda8ce3487c0"
#api key for the account test1732025@gmail.com created on 7/3/2025
#API_KEY="21368a5846046ad556073eba52a81055faae20db11283227e9bc464599ceae97"
#1st API key is new API key of account AVirus Account created on "5/27/2025"
#API_KEY="0daad9cc595099ee70a09c08e4692b05a9b44a87c0d2d2d0a4b56db31f4b5432"
#2nd API Key is for account mcscyberdiv@gmail.com account created on "5/27/2025"
#API_KEY="8595fb90a426f76f966e70a65b1a133c41d3fd7d962cfb6929431e0289b273fe"
#3rd  API Key is for account virushashes@gmail.com account created on "5/27/2025"
#API_KEY="cd4a67f124a6df9a6bb31d375c95eaac89ff47e791c2f4451abfddd66d49cebc"
#4rth API key for account arafah200125@gmail.com created on "6/5/2025"
#API_KEY="6bd1da0287ab0c16ace8d60a71396088faa95fb63dc862cf4a8c693f91f43083"
#API_KEY = "066c81301e3c7433ae09470e77093d061bfe4622d7300936326ffe8cc1c26065"
#API_KEY = "d6643621e4f9e4dcff0df1abbfe1867ef37f060a475b9f1aab1c1901972a40fb"
#API_KEY="d209ed9afd01408c7266f04c4d3d0b8ae2776b3f3eafaaf9745d2a2963f7976e"
#API_KEY="94ec7483339e29c672dcd890a5c33381883238e9a2c51b8c3e4a11dd70f8ab54"
#API_KEY="73b2a2774f5ac572305870854dcb4375e558514838eb33ea8bc88a2b81781bbd"
#API_KEY="29e1f460114b5ac8c67e386f1be723f655aba689f2bacfac2d99ddd95906dc19"
#API_KEY="48655d7f13e1be60f3092ced2c459a7b53507e3aa0323938396e29c87a058281"
#API_KEY = "02b42e5abf903b99f29f3bad1a13165979a6a9e1a71a201616ad2c0fae11a158"
#API_KEY="114101dfecc63da72b6077566472fe00f7bee30e48281b18de873643f5109645"

input_file = r"C:\Users\HP\Desktop\hashes\remaining.xlsx"
output_file = r"C:\Users\HP\Desktop\hashes\remprocessed.csv"

# ✅ Load all MD5 hashes from Excel
df = pd.read_excel(input_file, engine='openpyxl')
hash_list = df.iloc[:, 0].dropna().tolist()  # Only the first column = MD5

# ✅ Load processed hashes from output CSV if exists
if os.path.exists(output_file):
    existing_df = pd.read_csv(output_file)
    if 'MD5' in existing_df.columns:
        existing_df = existing_df.drop_duplicates(subset='MD5')
        existing_df.to_csv(output_file, index=False)
        processed_hashes = set(existing_df['MD5'].dropna())
    else:
        processed_hashes = set()
else:
    processed_hashes = set()

# ✅ Resume progress
last_processed_index = -1
for idx, md5 in enumerate(hash_list):
    if md5 in processed_hashes:
        last_processed_index = idx

start_index = last_processed_index + 1
print(f"Resuming from index {start_index} of {len(hash_list)} total hashes")

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def get_virustotal_data(md5):
    headers = {"x-apikey": API_KEY}
    if not md5 or pd.isna(md5):
        return [md5, 'Invalid', 'Invalid', 'Invalid']

    response = requests.get(VT_URL.format(md5), headers=headers)
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

        return [md5, f"{mal_score}({overall_score})", creation_time, last_submission]
    else:
        print(f"No data found for: {md5} (status {response.status_code})")
        return [md5, 'Error', 'Error', 'Error']

results = []
processed_count = 0

for i in range(start_index, len(hash_list)):
    md5 = hash_list[i]

    if md5 in processed_hashes:
        continue

    print(f"Processing {md5} ({i+1}/{len(hash_list)})")
    result = get_virustotal_data(md5)
    results.append(result)
    processed_hashes.add(md5)
    processed_count += 1

    # ✅ Save every 10 results
    if len(results) >= 10:
        temp_df = pd.DataFrame(results, columns=['MD5', 'MalScore', 'Creation Time', 'Last Submission'])
        if os.path.exists(output_file):
            combined = pd.concat([pd.read_csv(output_file), temp_df]).drop_duplicates(subset='MD5')
        else:
            combined = temp_df
        combined.to_csv(output_file, index=False)
        results.clear()

    # ✅ Stop at 500 daily requests
    if processed_count >= 500:
        print("Reached daily limit (500 requests). Stopping.")
        break

# ✅ Save remaining results
if results:
    temp_df = pd.DataFrame(results, columns=['MD5', 'MalScore', 'Creation Time', 'Last Submission'])
    if os.path.exists(output_file):
        combined = pd.concat([pd.read_csv(output_file), temp_df]).drop_duplicates(subset='MD5')
    else:
        combined = temp_df
    combined.to_csv(output_file, index=False)

print(f"✅ All done! Results saved to: {output_file}")