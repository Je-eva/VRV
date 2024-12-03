import re
import csv
from collections import defaultdict

# Threshold for flagging suspicious login attempts
FAILED_LOGIN_THRESHOLD = 10  

def parse_log(file_path):
    """ Reads log data from a file and returns it as a list of lines. """
    with open(file_path, 'r') as file:
        return file.readlines()

def analyze_logs(log_data):
    """ Analyzes log data to count requests per IP, endpoint access, and failed logins. """
    ip_request_counts = defaultdict(int)
    endpoint_access_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regex pattern to extract IP, endpoint, and status code
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).+"(?P<method>[A-Z]+) (?P<endpoint>/[^\s]*) HTTP.*" (?P<status>\d+)'

    for log_entry in log_data:
        match = re.search(log_pattern, log_entry)
        if match:
            ip = match.group('ip')
            endpoint = match.group('endpoint')
            status_code = int(match.group('status'))

            ip_request_counts[ip] += 1
            endpoint_access_counts[endpoint] += 1

            if status_code == 401:  # Increment failed login count for unauthorized attempts
                failed_logins[ip] += 1

    return ip_request_counts, endpoint_access_counts, failed_logins

def save_to_csv(ip_counts, endpoint_counts, failed_logins, output_file):
    """  Saves the analysis results to a CSV file. """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts.items())
        writer.writerow([])

        # Write endpoint access counts
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerows(endpoint_counts.items())
        writer.writerow([])

        # Write failed login attempts that exceed the threshold
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows((ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD)

def main():
    """ Main function to parse, analyze, and save log analysis results. """
    log_data = parse_log('sample.log')  # Read the log file
    ip_counts, endpoint_counts, failed_logins = analyze_logs(log_data)

    # Print summary of analysis
    print("Requests Per IP:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")

    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    print(f"\nMost Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity:")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip}: {count} failed attempts")

    # Save results to a CSV file
    save_to_csv(ip_counts, endpoint_counts, failed_logins, 'log_analysis_results.csv')

if __name__ == "__main__":
    main()
