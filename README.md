# Scripting-CA1-

Group members:
  1. Nithin kumaran C00313547
  2. Joel Biju  C00312179
  3. Emmett Leahy C00311509

#  Security Log Analysis Tool

A Python-based security log analysis tool that detects brute force attacks and suspicious activities from SSH and web server logs.

##  Features

###  Security Detection
- **Brute Force Attack Detection** - Identifies clusters of failed login attempts
- **Suspicious Tool Usage** - Detects hacking tools like sqlmap, curl, wget
- **GeoIP Tracking** - Maps attacker IPs to countries (public IPs only)
- **Multi-log Support** - Parses both SSH (`auth.log`) and Apache access logs

###  Visualization
- **Interactive CLI Menu** -terminal interface with Questionary
- **Matplotlib Charts** -  GUI visualizations

## Prerequisites
- Python 3.8 or higher
- pip package manager

## librarys needed
```bash
pip install matplotlib
pip install geocoder
```




