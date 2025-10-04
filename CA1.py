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



def parse_http_line(line):
    try:
        split_line = line.split()
        ip = split_line[0]

        # token looks like: '[04/Oct/2025:12:34:56' -> remove leading '['
        ts_token = split_line[3][1:]
        # ts_token example: "04/Oct/2025:12:34:56"
        # Reformat to "2025 Oct 04 12:34:56" to match your "%Y %b %d %H:%M:%S" spec
        try:
            day, month, rest = ts_token.split('/', 2)      # ['04','Oct','2025:12:34:56']
            year, time_part = rest.split(':', 1)           # ['2025', '12:34:56']
            ts_formatted = f"{year} {month} {day} {time_part}"
            ts = datetime.strptime(ts_formatted, "%Y %b %d %H:%M:%S")
        except Exception:
            # fallback: try apache format directly
            try:
                ts = datetime.strptime(ts_token.split()[0], "%d/%b/%Y:%H:%M:%S")
            except Exception:
                ts = None

        request = " ".join(split_line[5:8]).strip('"') if len(split_line) > 7 else ""
        status = split_line[8] if len(split_line) > 8 else ""
        ua = " ".join(split_line[11:]).strip('"').lower() if len(split_line) > 11 else ""

        event_type = "other"
        if status.startswith('4') or status.startswith('5'):
            event_type = "failed"
        if any(x in request.lower() for x in ['admin', 'login', 'phpinfo', 'secret', 'passwd']):
            event_type = "failed"
        if any(tool in ua for tool in ['sqlmap', 'curl', 'wget']):
            event_type = "failed"

        # return values: ts, ip, event_type, request, status, ua
        return ts, ip, event_type, request, status, ua

    except Exception:
        return None, None, "other", None, None, None


def is_http_line(line):
    return line[0].isdigit() and ("[" in line and "]" in line and '"' in line)

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list) 
    with open(LOGFILE) as f: 
        for line in f: 
            if is_http_line(line):
                ts,ip,event,request,status,ua = parse_http_line(line)
                if ts and ip:
                    request_lower = request.lower() #converts the requests to lower case
                    ua_lower = ua.lower() #converts the ua to lower case 
                    keywords = ['login', 'admin', 'phpinfo', 'secret', 'passwd']
                    tools = ['sqlmap', 'curl', 'wget']
                    if any(k in request_lower for k in keywords) and any(t in ua_lower for t in tools):
                        sucpicious_tools_ip.add(ip)


            else:    
                ts, ip, event = parse_auth_line(line) 
                #This if statement will run for failed attement for either https and ssh logs
            if ts and ip and event == "failed":   
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

print("IPs using tools and accessing suspicious paths: ")
for ip in sucpicious_tools_ip:
    print(ip)

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
