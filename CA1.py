import json
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as  plt
import time
import geocoder as g
import ipaddress
import re
import questionary

start = time.time()     #timing gear
LOGFILE = "log_file.log"
sorted_list=[] 
output={}
suspicious_tools_ip = set()     #a set of all suspicious unique ip address

# Color codes for terminal output
RESET = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW_BG = '\033[103m'
MAGENTA = '\033[95m'
BLUE = '\033[94m'

def parse_auth_line(line):
    parts = line.split()
    ts_str = " ".join(parts[0:3])   #gets the date with a space between
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")   # adds 2025 to the start of the log date
    except ValueError:
        ts = None

    ip = None   #sets the ip to none initially
    event_type = "other"    #sets the event type to other initially
    country = None

    if "Failed password" in line:
        event_type = "failed" 
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted" 

    if " from " in line:    #looking for ip using from keyword
        try:
            idx = parts.index("from")   #logs the index of the word from
            ip = parts[idx+1]   #gets ip address
            ip= ip.strip(',')  #removes any commas
        except (ValueError, IndexError):
            ip = None

    ip_pattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}') #used to split up the ip address into 4 octets

    # Validate IP format
    if ip and not ip_pattern.fullmatch(ip):
        ip = None # if fail returns none

    #check if the ip is private or public
    if ip:
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private #checks if the ip is private or not

            # Perform GeoIP lookup only if not private
            if not is_private:
                try:
                    geo = g.ip(ip) # gets the ip address details using geocoder
                    if geo and geo.country:
                        country = geo.country
                    else:
                        country = "Unknown"
                except Exception:
                    country = "Lookup Failed"
            else:
                country = "Private Address"

        except ValueError:
            ip = None
            is_private = None
            country = None

    return ts, ip, event_type, country

def parse_http_line(line):
    try:
        split_line = line.split()   #splits the log line using spaces
        ip = split_line[0]  #Apache log files have ip address in the beginning

        ts_token = split_line[3][1:]    #gets the split up date and removes the [
        try:
            day, month, rest = ts_token.split('/', 2)      # splits the [10/Mar/2025:15:46:11 +0000] to ['10','March','2025:15:46:11 +0000']
            year, time_part = rest.split(':', 1)           # splits this 2025:15:46:11 +0000 to ['2025','15:46:11 +0000'] because of ,1)
            ts_formatted = f"{year} {month} {day} {time_part}"  #puts all the split elements from above into a format string
            ts = datetime.strptime(ts_formatted, "%Y %b %d %H:%M:%S")   # reformatted time stamp string
        except Exception:   #error handling logic
            try:
                ts = datetime.strptime(ts_token.split()[0], "%d/%b/%Y:%H:%M:%S")
            except Exception:
                ts = None

        if len(split_line) > 7:
    # Safely select and join the elements, then remove the quotes
            request_tokens = split_line[5:8]
            request = " ".join(request_tokens).strip('"')
        else:
            request = ""

    # --- 2. Get the Status Code (Index 8) ---
        if len(split_line) > 8:
            status = split_line[8]
        else:
            status = ""

    # --- 3. Get the User Agent (Index 11 to the End) ---
        if len(split_line) > 11:
    # Safely select ALL remaining elements
            ua_tokens = split_line[11:]
    # Join them, remove quotes, and convert to lowercase
            ua = " ".join(ua_tokens).strip('"').lower()
        else:
            ua = ""

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
    return line[0].isdigit() and ("[" in line and "]" in line and '"' in line) # checking the apache style log entries and return boolean value

def analyze_logs():
    """Analyze logs and return incidents and suspicious IPs"""
    per_ip_timestamps = defaultdict(list)
    suspicious_tools_ip = set()
    
    with open(LOGFILE) as f: 
        for line in f: 
            if is_http_line(line):
                ts, ip, event, request, status, ua = parse_http_line(line)
                if ts and ip:
                    request_lower = request.lower() #converts the requests to lower case
                    ua_lower = ua.lower() #converts the ua to lower case 
                    keywords = ['login', 'admin', 'phpinfo', 'secret', 'passwd']
                    tools = ['sqlmap', 'curl', 'wget']
                    if any(k in request_lower for k in keywords) and any(t in ua_lower for t in tools):
                        suspicious_tools_ip.add(ip)

            else:    
                ts, ip, event, country = parse_auth_line(line)

            #This if statement will run for failed attement for either https and ssh logs
            if ts and ip and event == "failed":   
                per_ip_timestamps[ip].append(ts)

    # Detect brute force incidents
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
                # Get country for this IP
                country = "Unknown"
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private:
                        geo = g.ip(ip)
                        country = geo.country if geo and geo.country else "Unknown"
                    else:
                        country = "Private Address"
                except:
                    country = "Lookup Failed"
                    
                incidents.append({
                    "ip": ip,
                    "count": count,
                    "first": times[i].isoformat(),
                    "last": times[j].isoformat(),
                    "country": country
                })
                # advance i past this cluster to avoid duplicate overlapping reports:
                i = j + 1
            else:
                i += 1
                
    return incidents, suspicious_tools_ip, per_ip_timestamps

def display_incidents(incidents):
    """Display incidents in a formatted way"""
    print('\n' + '=' * 52 + ' INCIDENT REPORT ' + '=' * 52 + '\n')
    print(f"{len(incidents)} brute-force incidents found")
    print('*----------------------------------*')

    grouped = defaultdict(list)
    for incident in incidents:
        grouped[incident['ip']].append(incident)

    # Print each IP once, then all its details
    for ip, records in grouped.items():
        ip_colored = f"{CYAN}{YELLOW_BG}{ip}{RESET}"
        country_colored = f"{GREEN}{records[0]['country']}{RESET}"
        print(f"IP: {ip_colored}  Country: {country_colored}")

        for record in records:
            count = f"{RED}{record['count']}{RESET}"
            first = f"{GREEN}{record['first']}{RESET}"
            last = f"{GREEN}{record['last']}{RESET}"
            print(f"  Count: {count}, First: {first}, Last: {last}")

        print(f"{MAGENTA}{'*' * 100}{RESET}")

def display_suspicious_ips(suspicious_tools_ip):
    """Display suspicious IPs using tools"""
    print("\nIPs using tools and accessing suspicious paths: ")
    for ip in suspicious_tools_ip:
        print(f"{CYAN}{YELLOW_BG}{ip}{RESET}")
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private:
                geo = g.ip(ip)
                country = geo.country if geo and geo.country else "Unknown"
                print(f"  Country: {GREEN}{country}{RESET}")
            else:
                print(f"  Type: {BLUE}Private Address{RESET}")
        except:
            print(f"  Geolocation: {RED}Failed{RESET}")
        print(f"{MAGENTA}{'-'*30}{RESET}")

def create_histogram(incidents):
    """Create histogram using plotext for terminal display"""
    if not incidents:
        print(f"{RED}No incidents to plot.{RESET}")
        return
        

    list_ips = []
    list_count = []
    colors = ['red', 'yellow', 'pink']
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

def save_results_to_file(incidents, suspicious_tools_ip, filename="security_report.txt"):
    """Save analysis results to a file"""
    with open(filename, 'w') as f:
        f.write("SECURITY ANALYSIS REPORT\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"BRUTE FORCE INCIDENTS ({len(incidents)} found)\n")
        f.write("-" * 40 + "\n")
        for incident in incidents:
            f.write(f"IP: {incident['ip']}\n")
            f.write(f"  Count: {incident['count']}\n")
            f.write(f"  First: {incident['first']}\n")
            f.write(f"  Last: {incident['last']}\n")
            f.write(f"  Country: {incident['country']}\n\n")
        
        f.write(f"SUSPICIOUS TOOL USAGE ({len(suspicious_tools_ip)} IPs)\n")
        f.write("-" * 40 + "\n")
        for ip in suspicious_tools_ip:
            f.write(f"IP: {ip}\n")
    
    print(f"{GREEN}Results saved to {filename}{RESET}")

def main_menu():
    """Main interactive menu"""
    incidents = []
    suspicious_tools_ip = set()
    per_ip_timestamps = defaultdict(list)
    
    while True:
        choice = questionary.select(
            "Security Log Analysis Menu",
            choices=[
                "1. Analyze Logs",
                "2. Show Brute Force Incidents", 
                "3. Show Suspicious Tool Usage",
                "4. Generate Bar Chart of Top Attackers",
                "5. Save Results to File",
                "6. Exit"
            ]
        ).ask()

        if choice == "1. Analyze Logs":
            print(f"{BLUE}Analyzing logs...{RESET}")
            incidents, suspicious_tools_ip, per_ip_timestamps = analyze_logs()
            print(f"{GREEN}Analysis complete!{RESET}")
            print(f"  - Found {len(incidents)} brute force incidents")
            print(f"  - Found {len(suspicious_tools_ip)} suspicious IPs using tools")
            
        elif choice == "2. Show Brute Force Incidents":
            if not incidents:
                print(f"{YELLOW_BG}No incidents found. Please analyze logs first.{RESET}")
                continue
            display_incidents(incidents)
            
        elif choice == "3. Show Suspicious Tool Usage":
            if not suspicious_tools_ip:
                print(f"{YELLOW_BG}No suspicious IPs found. Please analyze logs first.{RESET}")
                continue
            display_suspicious_ips(suspicious_tools_ip)
            
        elif choice == "4. Generate Bar Chart of Top Attackers":
            if not incidents:
                print(f"{YELLOW_BG}No incidents found. Please analyze logs first.{RESET}")
                continue
            create_histogram(incidents)
            
        elif choice == "5. Save Results to File":
            if not incidents and not suspicious_tools_ip:
                print(f"{YELLOW_BG}No data to save. Please analyze logs first.{RESET}")
                continue
            filename = questionary.text("Enter filename:", default="security_report.txt").ask()
            save_results_to_file(incidents, suspicious_tools_ip, filename)
            
        elif choice == "6. Exit":
            print(f"{GREEN}Goodbye!{RESET}")
            break
        
        # Pause between actions
        if choice != "6. Exit":
            questionary.press_any_key_to_continue(f"press any key to continue....").ask()

if __name__ == "__main__":
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{CYAN}    SECURITY LOG ANALYSIS TOOL{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    main_menu()