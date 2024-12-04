
Log Analysis Script
Overview
This project is a Python-based log analysis tool designed to process server log files and extract meaningful insights. It includes functionalities to count requests per IP address, identify the most frequently accessed endpoints, and detect suspicious activity such as brute force login attempts.

Features
Count Requests per IP Address:

Extracts all IP addresses from the log file.
Calculates the number of requests made by each IP.
Displays results in descending order of request counts.
Identify the Most Frequently Accessed Endpoint:

Analyzes log entries to find the most accessed resource (e.g., URLs, paths).
Outputs the endpoint and the count of accesses.
Detect Suspicious Activity:

Identifies IPs with failed login attempts (e.g., HTTP 401 status).
Flags IPs with failed attempts exceeding a configurable threshold (default: 10).
CSV Output:

Saves analysis results to log_analysis_results.csv:
Requests per IP: IP Address and Request Count.
Most Accessed Endpoint: Endpoint and Access Count.
Suspicious Activity: IP Address and Failed Login Count.
How to Run
Prerequisites
Python 3.x installed on your machine.
Steps
Clone the repository:
git clone https://github.com/<your-username>/log_analysis.git
cd log_analysis
Ensure sample.log is present in the directory.

Run the script:
python log_analysis.py

View results:
In the terminal output.
In the log_analysis_results.csv file created in the same directory.



