import re
import csv
from collections import defaultdict

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = 'sample.log'
CSV_OUTPUT_FILE = 'log_analysis_results.csv'


def parse_log_file(file_path):
    """Parse the log file and extract relevant information."""
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            ip_address = ip_match.group(1) if ip_match else None

            # Extract endpoint and status code
            endpoint_match = re.search(r'"[A-Z]+\s(\S+)\sHTTP', line)
            status_match = re.search(r'HTTP/\d+\.\d+\"\s(\d+)', line)

            endpoint = endpoint_match.group(1) if endpoint_match else None
            status_code = int(status_match.group(1)) if status_match else None

            # Update IP request counts
            if ip_address:
                ip_requests[ip_address] += 1

            # Update endpoint request counts
            if endpoint:
                endpoint_requests[endpoint] += 1

            # Detect failed login attempts
            if status_code == 401 or 'Invalid credentials' in line:
                if ip_address:
                    failed_login_attempts[ip_address] += 1

    return ip_requests, endpoint_requests, failed_login_attempts


def find_most_accessed_endpoint(endpoint_requests):
    """Find the most frequently accessed endpoint."""
    if not endpoint_requests:
        return None, 0
    return max(endpoint_requests.items(), key=lambda item: item[1])


def save_to_csv(ip_requests, endpoint, endpoint_count, failed_login_attempts, output_file):
    """Save results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP section
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint section
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint, endpoint_count])

        # Write Suspicious Activity section
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_login_attempts.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])


def main():
    # Parse log file
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(LOG_FILE)

    # Find the most frequently accessed endpoint
    most_accessed_endpoint, access_count = find_most_accessed_endpoint(endpoint_requests)

    # Display results
    print("\nRequests per IP Address:")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {access_count} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in failed_login_attempts.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, access_count, failed_login_attempts, CSV_OUTPUT_FILE)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
