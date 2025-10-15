import requests
import pandas as pd
import time
import os

# ========= CONFIG =========
API_KEY = "21368a5846046ad556073eba52a81055faae20db11283227e9bc464599ceae97"
input_file = r"C:\Users\HP\Desktop\hashes\errror.csv"     # CSV with one column: Url
output_file = r"C:\Users\HP\Desktop\hashes\PENDING_urls.csv" # output path
VT_URL = "https://www.virustotal.com/api/v3/urls/{}"
VT_LINK = "https://www.virustotal.com/gui/url/{}"

# ========= LOAD URL LIST =========
df = pd.read_csv(input_file)
url_list = df["Url"].dropna().tolist()

# ========= LOAD ALREADY PROCESSED =========
if os.path.exists(output_file):
    existing_df = pd.read_csv(output_file)
    processed = set(existing_df["Url"].dropna())
else:
    processed = set()

headers = {"x-apikey": API_KEY}
results, batch = [], []

def vt_url_id(raw_url: str) -> str:
    """VT requires URL-safe base64 (without '=' padding)."""
    import base64
    b64 = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
    return b64

def get_vt_data(url: str):
    try:
        url_id = vt_url_id(url)
        r = requests.get(VT_URL.format(url_id), headers=headers, timeout=30)
        if r.status_code != 200:
            return [url, "Error", "Error", "Error", "Error", "Error"]

        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        malscore = stats.get("malicious", 0)

        first_sub = data.get("first_submission_date")
        last_sub = data.get("last_submission_date")
        last_analysis = data.get("last_analysis_date")

        def fmt(ts):
            return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) if ts else "N/A"

        return [
            url,
            malscore,
            fmt(first_sub),
            fmt(last_sub),
            fmt(last_analysis),
            VT_LINK.format(url_id),
        ]
    except Exception as e:
        print(f"⚠️ Error for {url}: {e}")
        return [url, "Error", "Error", "Error", "Error", "Error"]


for idx, u in enumerate(url_list, start=1):
    if u in processed:
        continue

    print(f"[{idx}/{len(url_list)}] Checking {u}")
    row = get_vt_data(u)
    batch.append(row)
    processed.add(u)

    if len(batch) >= 10:       # write every 10
        cols = ["Url", "MalScore", "FirstSubmission",
                "LastSubmission", "LastAnalysis", "VT_Link"]
        new_df = pd.DataFrame(batch, columns=cols)
        if os.path.exists(output_file):
            new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Url")
        new_df.to_csv(output_file, index=False)
        batch.clear()

    time.sleep(10)  # respect ~4 requests/min (public API)

# Flush remainder
if batch:
    cols = ["Url", "MalScore", "FirstSubmission",
            "LastSubmission", "LastAnalysis", "VT_Link"]
    new_df = pd.DataFrame(batch, columns=cols)
    if os.path.exists(output_file):
        new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Url")
    new_df.to_csv(output_file, index=False)

print(f"✅ Done! Saved to {output_file}")
