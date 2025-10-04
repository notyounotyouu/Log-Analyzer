# lab2.3_starter.py
import json
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
import matplotlib.pyplot as plt
import time

start = time.time() #timing gear
LOGFILE = "log_file.log"
sorted_list=[] 
output={}
sucpicious_tools_ip = set() #


def parse_auth_line(line):
    parts = line.split()
    ts_str = " ".join(parts[0:3]) 
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S") 

    except ValueError:
        ts = None
    ip = None
    event_type = "other" 
    if "Failed password" in line:
        event_type = "failed" 
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted" 
    if " from " in line: 
        try:
            idx = parts.index("from") 
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list) # dictionary declaration
    with open(LOGFILE) as f: #opening the file
        for line in f: #chopping it line by line
            ts, ip, event = parse_auth_line(line) # calling the function and returning the values
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts)

    for ip, ts in per_ip_timestamps.items():
        sorted_ts = sorted(ts) # sorting the timestamps
        formatted_ts = [t.strftime("%Y-%b-%d %H:%M:%S") for t in sorted_ts] # formatting the timestamps and putting int a list
        output[ip] = formatted_ts # storing the formatted timestamps in the output dictionary
    
incidents = [] # make a list called incidents to store the results
window = timedelta(minutes=10) #define the time delta window of 10 minutes
for ip, times in per_ip_timestamps.items(): #iterate through the dictionary
    times.sort() #sort timestamps
    n = len(times) #get the length of the timestamps list
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5: # if there are 5 or more failed attempts in the window
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            # advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1
        else:
            i += 1
print(f"{len(incidents)} brute-force incidents found:")
for i in incidents:
    print(i)

#make a bar chart of the top attacker IPs
list_ips=[]
list_count=[]
colors=['red','yellow','pink']
for i in incidents:
    list_ips.append(i["ip"])
    list_count.append(i["count"])
plt.figure(figsize=(12,5))
plt.bar(list_ips, list_count)
plt.title("Top attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
end = time.time()
print("Elapsed:", end-start, "seconds")
"""    

plt.figure(figsize=(12,5))

plt.figure(figsize=(12,5))

# Histogram of failed attempts
plt.hist(list_count, bins=10, color='skyblue', edgecolor='black')  # adjust bins as needed

# Labels and title
plt.title("Distribution of Failed Attempts per IP")
plt.xlabel("Number of Failed Attempts")
plt.ylabel("Number of IPs")

plt.tight_layout()
plt.savefig("failed_attempts_hist.png")
plt.show()"""

#this shit is for pushing  
