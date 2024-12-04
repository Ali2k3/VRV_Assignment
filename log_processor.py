import re
import csv
import argparse
from collections import defaultdict, Counter
import os


class LogAnalyzer:
    def __init__(self, log_file):
        """
        Initialize the LogAnalyzer with the given log file.

        Args:
            log_file (str): Path to the log file to be analyzed.
        """
        self.log_file = log_file
        self.ip_requests = Counter()
        self.endpoint_requests = Counter()
        self.failed_logins = defaultdict(int)

    def parse_log(self):
        """
        Parse the log file line by line and populate data structures
        for analysis.
        """
        with open(self.log_file, 'r') as file:
            for line in file:
                self._process_line(line)

    def _process_line(self, line):
        """
        Process a single line from the log file to extract relevant data.

        Args:
            line (str): A single log entry.
        """
        # Extract IP addresses
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
        if ip_match:
            ip = ip_match.group(0)
            self.ip_requests[ip] += 1

        # Extract endpoints
        endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD) ([^\s]+)', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            self.endpoint_requests[endpoint] += 1

        # Detect failed login attempts (401 status or specific failure messages)
        if '401' in line or 'Invalid credentials' in line:
            if ip_match:
                self.failed_logins[ip] += 1

    def get_requests_per_ip(self):
        """
        Get the number of requests per IP address.

        Returns:
            list: List of tuples containing IP addresses and their request counts, sorted in descending order.
        """
        return self.ip_requests.most_common()

    def get_most_frequent_endpoint(self):
        """
        Get the most frequently accessed endpoint.

        Returns:
            tuple: The endpoint and its access count.
        """
        if self.endpoint_requests:
            return self.endpoint_requests.most_common(1)[0]
        return None, 0

    def get_suspicious_activity(self):
        """
        Identify IPs exceeding 10 failed login attempts.

        Returns:
            dict: Dictionary of IP addresses and their failed login counts.
        """
        return {ip: count for ip, count in self.failed_logins.items() if count > 10}

    def save_results_to_csv(self, output_file):
        """
        Save analysis results to a CSV file.

        Args:
            output_file (str): Path to the CSV file.
        """
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write Requests per IP
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in self.get_requests_per_ip():
                writer.writerow([ip, count])

            # Write Most Accessed Endpoint
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint', 'Access Count'])
            endpoint, count = self.get_most_frequent_endpoint()
            writer.writerow([endpoint, count])

            # Write Suspicious Activity
            writer.writerow([])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in self.get_suspicious_activity().items():
                writer.writerow([ip, count])

    def display_results(self):
        """
        Display the analysis results in the terminal in a clear format.
        """
        print("Requests per IP Address:")
        print("IP Address   | Request Count")
        print("-----------------------------------------")
        for ip, count in self.get_requests_per_ip():
            print(f"{ip}    | {count}")

        print("\nMost Frequently Accessed Endpoint:")
        endpoint, count = self.get_most_frequent_endpoint()
        print(f"{endpoint} (Accessed {count} times)")

        print("\nSuspicious Activity Detected:")
        print("IP Address  |   Failed Login Attempts")
        for ip, count in self.get_suspicious_activity().items():
            print(f"{ip}   |   {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze server log files.")
    parser.add_argument(
        "log_file",
        type=str,
        help="Path to the log file to analyze."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Path to the output CSV file. Default is based on the log file name."
    )

    args = parser.parse_args()

    # Generate default CSV file name based on the log file name
    log_file_basename = os.path.basename(args.log_file)
    default_output_csv = f"log_analysis_results_{log_file_basename}.csv"
    output_csv = args.output or default_output_csv

    # Run the analysis
    analyzer = LogAnalyzer(args.log_file)
    analyzer.parse_log()
    analyzer.display_results()
    analyzer.save_results_to_csv(output_csv)
    print(f"Log file processed. Results saved to {output_csv}")
