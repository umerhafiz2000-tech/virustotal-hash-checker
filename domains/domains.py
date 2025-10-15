# import requests, pandas as pd, time, os
# import re
# # ===== CONFIG =====
# API_KEY = "21368a5846046ad556073eba52a81055faae20db11283227e9bc464599ceae97"
# input_file = r"C:\Users\HP\Desktop\hashes\domains.csv"       # one column: Domain
# output_file = r"C:\Users\HP\Desktop\hashes\vt_domains.csv"
# VT_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"
# headers = {"x-apikey": API_KEY}

# # ===== LOAD =====
# df = pd.read_csv(input_file)
# domain_list = df["Domains"].dropna().tolist()

# if os.path.exists(output_file):
#     existing = pd.read_csv(output_file)
#     processed = set(existing["Domains"].dropna())
# else:
#     processed = set()

# def get_domain_info(domain):
#     try:
#         r = requests.get(VT_DOMAIN.format(domain), headers=headers, timeout=15)
#         if r.status_code != 200:
#             return [domain, "Error", "", "", "", "", "", ""]
#         data = r.json()["data"]["attributes"]

#         malscore = data.get("last_analysis_stats", {}).get("malicious", 0)
#         vt_link = f"https://www.virustotal.com/gui/domain/{domain}"

#         whois = data.get("whois", {})
#         creation = whois.get("creation_date", "")
#         updated  = whois.get("updated_date", "")
#         expiry   = whois.get("expiration_date", "")

#         return [domain, malscore, vt_link, creation, updated, expiry]

#     except Exception as e:
#         print(f"⚠️ {domain}: {e}")
#         return [domain, "Error", "", "", "", ""]

# batch = []
# for idx, dom in enumerate(domain_list, 1):
#     if dom in processed:
#         continue
#     print(f"[{idx}/{len(domain_list)}] Checking {dom}")
#     row = get_domain_info(dom)
#     batch.append(row)
#     processed.add(dom)

#     if len(batch) >= 10:
#         cols = ["Domain", "MalScore", "VT_Link",
#                 "CreationDate", "UpdatedDate", "RegistryExpiry"]
#         new_df = pd.DataFrame(batch, columns=cols)
#         if os.path.exists(output_file):
#             new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
#         new_df.to_csv(output_file, index=False)
#         batch.clear()
#     time.sleep(16)    # respect VT public rate limit

# if batch:
#     cols = ["Domain", "MalScore", "VT_Link",
#             "CreationDate", "UpdatedDate", "RegistryExpiry"]
#     new_df = pd.DataFrame(batch, columns=cols)
#     if os.path.exists(output_file):
#         new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
#     new_df.to_csv(output_file, index=False)

# print(f"✅ Done! Saved to {output_file}")





# import requests
# import pandas as pd
# import time
# import os
# import re

# # ========= CONFIG =========
# API_KEY = "21368a5846046ad556073eba52a81055faae20db11283227e9bc464599ceae97"
# input_file = r"C:\Users\HP\Desktop\hashes\domains.csv"       # CSV with one column: Domain
# output_file = r"C:\Users\HP\Desktop\hashes\vt_domains.csv"   # Output CSV
# VT_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"

# headers = {"x-apikey": API_KEY}

# # ========= LOAD DOMAIN LIST =========
# df = pd.read_csv(input_file)
# domain_list = df["Domains"].dropna().tolist()

# # ========= LOAD ALREADY PROCESSED =========
# if os.path.exists(output_file):
#     existing_df = pd.read_csv(output_file)
#     processed = set(existing_df["Domains"].dropna())
# else:
#     processed = set()

# def parse_whois(whois_raw):
#     """
#     Extract CreationDate, UpdatedDate, RegistryExpiry from WHOIS text or dict.
#     """
#     creation = updated = expiry = ""
#     if isinstance(whois_raw, dict):
#         creation = whois_raw.get("creation_date", "")
#         updated  = whois_raw.get("updated_date", "")
#         expiry   = whois_raw.get("expiration_date", "")
#     elif isinstance(whois_raw, str):
#         c_match = re.search(r"Creation Date:\s*(.+)", whois_raw, re.I)
#         u_match = re.search(r"Updated Date:\s*(.+)", whois_raw, re.I)
#         e_match = re.search(r"(Registry Expiry Date|Registrar Registration Expiration Date):\s*(.+)", whois_raw, re.I)
#         if c_match: creation = c_match.group(1).strip()
#         if u_match: updated  = u_match.group(1).strip()
#         if e_match: expiry   = e_match.group(2).strip()
#     return creation, updated, expiry

# def get_domain_info(domain):
#     """
#     Query VirusTotal for domain info and parse malscore, link, and whois dates.
#     """
#     try:
#         if domain.endswith(".onion"):
#             return [domain, "", "", "", "", ""]  # Skip WHOIS for onion

#         r = requests.get(VT_DOMAIN.format(domain), headers=headers, timeout=15)
#         if r.status_code != 200:
#             return [domain, "Error", "", "", "", ""]
#         data = r.json()["data"]["attributes"]

#         malscore = data.get("last_analysis_stats", {}).get("malicious", 0)
#         vt_link = f"https://www.virustotal.com/gui/domain/{domain}"

#         whois_raw = data.get("whois", "")
#         creation, updated, expiry = parse_whois(whois_raw)

#         return [domain, malscore, vt_link, creation, updated, expiry]

#     except Exception as e:
#         print(f"⚠️ {domain}: {e}")
#         return [domain, "Error", "", "", "", ""]

# # ========= MAIN LOOP =========
# batch = []
# for idx, dom in enumerate(domain_list, start=1):
#     if dom in processed:
#         continue
#     print(f"[{idx}/{len(domain_list)}] Checking {dom}")
#     row = get_domain_info(dom)
#     batch.append(row)
#     processed.add(dom)

#     if len(batch) >= 10:  # write every 10 rows
#         cols = ["Domain", "MalScore", "VT_Link",
#                 "CreationDate", "UpdatedDate", "RegistryExpiry"]
#         new_df = pd.DataFrame(batch, columns=cols)
#         if os.path.exists(output_file):
#             new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
#         new_df.to_csv(output_file, index=False)
#         batch.clear()

#     time.sleep(16)  # Respect VT public rate limits (~4 req/min)

# # ========= FLUSH REMAINING =========
# if batch:
#     cols = ["Domain", "MalScore", "VT_Link",
#             "CreationDate", "UpdatedDate", "RegistryExpiry"]
#     new_df = pd.DataFrame(batch, columns=cols)
#     if os.path.exists(output_file):
#         new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
#     new_df.to_csv(output_file, index=False)

# print(f"✅ Done! Saved to {output_file}")


import requests
import pandas as pd
import time
import os
import re

# ========= CONFIG =========
API_KEY = "21368a5846046ad556073eba52a81055faae20db11283227e9bc464599ceae97"
input_file = r"C:\Users\HP\Desktop\hashes\domains.csv"       # CSV with one column: Domain
output_file = r"C:\Users\HP\Desktop\hashes\vt_domains.csv"   # Output CSV
VT_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"

headers = {"x-apikey": API_KEY}

# ========= LOAD DOMAIN LIST =========
df = pd.read_csv(input_file)
domain_list = df["Domains"].dropna().tolist()  

# ========= LOAD ALREADY PROCESSED =========
if os.path.exists(output_file):
    existing_df = pd.read_csv(output_file)
    processed = set(existing_df["Domain"].dropna())
else:
    processed = set()

# def parse_whois(whois_raw):
#     """
#     Extract CreationDate, UpdatedDate, RegistryExpiry from WHOIS text or dict.
#     """
#     creation = updated = expiry = ""
#     if isinstance(whois_raw, dict):
#         creation = whois_raw.get("creation_date", "")
#         updated  = whois_raw.get("updated_date", "")
#         expiry   = whois_raw.get("expiration_date", "")
#     elif isinstance(whois_raw, str):
#         c_match = re.search(r"Creation Date:\s*(.+)", whois_raw, re.I)
#         u_match = re.search(r"Updated Date:\s*(.+)", whois_raw, re.I)
#         e_match = re.search(r"(Registry Expiry Date|Registrar Registration Expiration Date):\s*(.+)", whois_raw, re.I)
#         if c_match: creation = c_match.group(1).strip()
#         if u_match: updated  = u_match.group(1).strip()
#         if e_match: expiry   = e_match.group(2).strip()
#     return creation, updated, expiry

def parse_whois(whois_raw):
    """
    Extract CreationDate, UpdatedDate, RegistryExpiry from WHOIS text or dict.
    Tries multiple possible field names.
    """
    creation = updated = expiry = ""

    # If WHOIS data is a dict (structured)
    if isinstance(whois_raw, dict):
        # List all possible key names for each field
        creation_keys = ["creation_date", "Create", "created_on", "Creation Date" , "Create Date" , "Create date"]
        updated_keys  = ["updated_date", "UpdatedDate", "changed", "Updated Date" , "Update date" , "Last updated on"]
        expiry_keys   = ["expiration_date", "ExpiryDate", "RegistryExpiry", "Registrar Registration Expiration Date" , "Expiry date"]

        # Pick the first key that exists and has a value
        for k in creation_keys:
            if k in whois_raw and whois_raw[k]:
                creation = str(whois_raw[k])
                break

        for k in updated_keys:
            if k in whois_raw and whois_raw[k]:
                updated = str(whois_raw[k])
                break

        for k in expiry_keys:
            if k in whois_raw and whois_raw[k]:
                expiry = str(whois_raw[k])
                break

    # If WHOIS data is a string (raw text)
    elif isinstance(whois_raw, str):
        # Use regex with multiple patterns
        c_match = re.search(r"(Creation Date|Created_On|created|Create Date|Create date|Create|creation_date|Creation Date):\s*(.+)", whois_raw, re.I)
        #u_match = re.search(r"(Updated Date|Changed|changed|Update date|Update Date|Last updated on):\s*(.+)", whois_raw, re.I)
        u_match = re.search(r"(Updated Date|Changed|changed|Update date|Update Date|Last Updated On|Last Updated|Last Update)\s*[:=]?\s*(.+)",whois_raw, re.I | re.MULTILINE)
        e_match = re.search(r"(Registry Expiry Date|Expiration Date|Expiry|Expiry date):\s*(.+)", whois_raw, re.I)

        if c_match: creation = c_match.group(2).strip()
        if u_match: updated  = u_match.group(2).strip()
        if e_match: expiry   = e_match.group(2).strip()

    return creation, updated, expiry


def get_domain_info(domain):
    """
    Query VirusTotal for domain info and parse malscore, link, and whois dates.
    """
    try:
       
        r = requests.get(VT_DOMAIN.format(domain), headers=headers, timeout=15)
        if r.status_code != 200:
            return [domain, "Error", "", "", "", ""]
        data = r.json()["data"]["attributes"]

        malscore = data.get("last_analysis_stats", {}).get("malicious", 0)
        vt_link = f"https://www.virustotal.com/gui/domain/{domain}"

        whois_raw = data.get("whois", "")
        creation, updated, expiry = parse_whois(whois_raw)

        return [domain, malscore, vt_link, creation, updated, expiry]

    except Exception as e:
        print(f"⚠️ {domain}: {e}")
        return [domain, "Error", "", "", "", ""]

# ========= MAIN LOOP =========
batch = []
for idx, dom in enumerate(domain_list, start=1):
    if dom in processed:
        continue
    print(f"[{idx}/{len(domain_list)}] Checking {dom}")
    row = get_domain_info(dom)
    batch.append(row)
    processed.add(dom)

    if len(batch) >= 5:  # write every 10 rows
        cols = ["Domain", "MalScore", "VT_Link",
                "CreationDate", "UpdatedDate", "RegistryExpiry"]
        new_df = pd.DataFrame(batch, columns=cols)
        if os.path.exists(output_file):
            new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
        new_df.to_csv(output_file, index=False)
        batch.clear()

    time.sleep(16)  # Respect VT public rate limits (~4 req/min)

# ========= FLUSH REMAINING =========
if batch:
    cols = ["Domain", "MalScore", "VT_Link",
            "CreationDate", "UpdatedDate", "RegistryExpiry"]
    new_df = pd.DataFrame(batch, columns=cols)
    if os.path.exists(output_file):
        new_df = pd.concat([pd.read_csv(output_file), new_df]).drop_duplicates(subset="Domain")
    new_df.to_csv(output_file, index=False)

print(f"✅ Done! Saved to {output_file}")
