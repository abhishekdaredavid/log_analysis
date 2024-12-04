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

bash
Copy code
git clone https://github.com/<your-username>/log_analysis.git
cd log_analysis
Ensure sample.log is present in the directory.

Run the script:

bash
Copy code
python log_analysis.py
View results:

In the terminal output.
In the log_analysis_results.csv file created in the same directory.
Sample Log File
The script uses a log file (e.g., sample.log) in the following format:

sql
Copy code
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
Replace the contents of sample.log with your log data to analyze different logs.

Output Example
Terminal Output
bash
Copy code
IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
bash
Copy code
Most Frequently Accessed Endpoint:
/home (Accessed 403 times)
bash
Copy code
Suspicious Activity Detected:
IP Address           Failed Login Attempts
203.0.113.5          12
192.168.1.100        56
CSV Output (log_analysis_results.csv)
IP Address	Request Count
192.168.1.1	234
203.0.113.5	187
Configuration
To modify the suspicious activity detection threshold:

Open log_analysis.py.
Update the THRESHOLD variable to your desired value:
python
Copy code
THRESHOLD = 15
