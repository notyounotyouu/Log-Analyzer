# lab2.3_starter.py
import json
import geocoder 
import questionary
from typing import Dict, Optional 
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
import matplotlib.pyplot as plt
import time

start = time.time() #timing gear
LOGFILE = "log_file.log"
sorted_list=[]
output={}


def parse_auth_line(line):
    parts = line.split()
    ts_str = " ".join(parts[0:3]) # this joins the first three parts i.e month, day, time
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S") # assume 2025 is the year year, month, day, hour, minute, second
    except Exception: # return none if timestamp parsing fails
        ts = None
    ip = None
    event_type = "other" # default event type
    if "Failed password" in line:
        event_type = "failed" #setting condition for failed event
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted" #setting condition for accepted event
    if " from " in line: #parsing the ip address
        try:
            idx = parts.index("from") # all the usual things
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
#Leahy - Made figure wider so as IPs don't overlap.
plt.figure(figsize=(20,5)) 
plt.bar(list_ips, list_count)
plt.title("Top attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
end = time.time()
print("Elapsed:", end-start, "seconds")

#Retrieves geograhpic locatin based on a provided ip address
class IPGeolocator:

    def Ip_Storing(self):
        #Stores Ip's and prevents un-needed api calls
        self.cache = {}

    #A method to get location data for an IP address.
    def locate_ip(self, ip_address: str) -> Optional[Dict]:
        if ip_address in self.cache: # checks if ip is already in cache (un-needed api calls)
            return self.cache[ip_address]

        try:
            geo = geocoder.ip(ip_address)
        #
            if geo.ok:
                #Returns basic information about IP
                location_data = {
                    'ip': ip_address,
                    'country': geo.country,
                    'region': geo.state,
                    'city': geo.city,
                    'latitude': geo.lat,
                    'longitude': geo.lng,
                    'isp': geo.org
                    }
                self.cache[ip_address] = location_data
                return location_data
            else:
                return None
        except Exception as e:
            print(f"Error locating IP {ip_address}: {e}")
        return None
        
print("\n" + "="*60)
print("GeoLocation Analysis")
print("="*60)

geolocator = IPGeolocator()
print("\nGeolocating incident IP's...")
for incident in incidents:
        location = geolocator.locate_ip(incident["ip"])
        if location:
            print(f"incident[ip]: {incident['ip']}, Location: {location['city']}, {location['region']},
                   {location['country']}, ISP: {location['isp']}")
        else:
            print(f"incident[ip]: {incident['ip']}, Location: Not found")

        
country_count = defaultdict(int)
country_ips = defaultdict(list)
for incident in incidents:
    location = geolocator.locate_ip(incident["ip"])
    if location and location['country']:
        country = location['country']
        country_count[country] += 1
        country_ips[country].append(incident["ip"])

print("\n" + "="*60)
print("Incident Summary by Country")
print("="*60)
for country, count in country_count.items():
    ips = country_ips[country]
    print(f"Country: {country}, Incidents: {count}, IPs: {', '.join(ips)}")

if country_count
    plt.figure(figsize=(10, 6))
    countries = list(country_count.keys())
    counts = list(country_count.values())

    plt.bar(countries, counts, color='blue')
    plt.title("Number of Incidents by Country")
    plt.xlabel("Country")
    plt.ylabel("Total Failed attempts")
    plt.xticks(rotation = 45)
    plt.tight_layout()
    plt.savefig("Attacks_by_country.png")
    plt.show()
    













            

        
            
        