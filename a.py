import re
import csv
from collections import defaultdict

# Defines a constant for identifying suspicious login attempts based on failed login count
MAX_FAILED_LOGINS = 10  

def read_log_file(file_path):
    """Reads the log file and returns all the lines as a list."""
    with open(file_path, 'r') as file:
        return file.readlines()

def process_logs(log_entries):
    """Processes the log entries and calculates statistics about IP requests, endpoints, and failed logins."""
    ip_statistics = defaultdict(int)
    endpoint_statistics = defaultdict(int)
    failed_attempts = defaultdict(int)

    # Regular expression pattern to extract the IP address, HTTP method, endpoint, and status code from each log entry
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).+"(?P<method>[A-Z]+) (?P<endpoint>/[^\s]*) HTTP.*" (?P<status>\d+)'

    for entry in log_entries:
        match = re.search(log_pattern, entry)
        if match:
            ip = match.group('ip')
            endpoint = match.group('endpoint')
            status = int(match.group('status'))

            # Increment counts for IP requests and endpoint accesses
            ip_statistics[ip] += 1
            endpoint_statistics[endpoint] += 1

            # Track failed login attempts (status code 401)
            if status == 401:
                failed_attempts[ip] += 1

    return ip_statistics, endpoint_statistics, failed_attempts

def export_to_csv(ip_stats, endpoint_stats, failed_logins, output_filepath):
    """Exports the analysis results into a CSV file."""
    with open(output_filepath, 'w', newline='') as file:
        writer = csv.writer(file)

        # Writing IP request counts
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_stats.items())
        writer.writerow([])

        # Writing endpoint access statistics
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerows(endpoint_stats.items())
        writer.writerow([])

        # Writing failed login attempts that exceed the defined threshold
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows((ip, count) for ip, count in failed_logins.items() if count > MAX_FAILED_LOGINS)

def run_analysis():
    """Main function to read logs, process them, and export the results."""
    log_entries = read_log_file('sample.log')  # Load log data
    ip_stats, endpoint_stats, failed_logins = process_logs(log_entries)

    # Display summary of log analysis
    print("IP Address Request Counts:")
    for ip, count in sorted(ip_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")

    most_visited_endpoint = max(endpoint_stats.items(), key=lambda x: x[1])
    print(f"\nMost Accessed Endpoint:\n{most_visited_endpoint[0]} (Accessed {most_visited_endpoint[1]} times)")

    print("\nIdentifying Suspicious Activity:")
    for ip, count in failed_logins.items():
        if count > MAX_FAILED_LOGINS:
            print(f"{ip}: {count} failed login attempts")

    # Save the results to a CSV file
    export_to_csv(ip_stats, endpoint_stats, failed_logins, 'log_analysis_output.csv')

if __name__ == "__main__":
    run_analysis()
