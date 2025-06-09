import argparse
import re
import json
from collections import defaultdict

class LogAnalyzer:
    def __init__(self, log_type, request_thresh=50, error_thresh=10):
        self.log_type = log_type
        self.request_thresh = request_thresh
        self.error_thresh = error_thresh
        self.ip_counts = defaultdict(int)
        self.ip_404_counts = defaultdict(int)
        self.flagged_requests = []

    def analyze_line(self, line):
        if self.log_type == "apache":
            self.analyze_apache(line)
        elif self.log_type == "ssh":
            self.analyze_ssh(line)
        else:
            raise ValueError("Unsupported log type")

    def analyze_apache(self, line):
        ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        status_match = re.search(r'" (\d{3}) ', line)
        agent_match = re.findall(r'"(.*?)"', line)

        if ip_match:
            ip = ip_match.group(1)
            self.ip_counts[ip] += 1

            if status_match and status_match.group(1) == "404":
                self.ip_404_counts[ip] += 1

            if agent_match and len(agent_match) > 2:
                user_agent = agent_match[-1].lower()
                if any(bad in user_agent for bad in ["curl", "sqlmap", "nikto"]):
                    self.flagged_requests.append({
                        "ip": ip,
                        "user_agent": user_agent,
                        "line": line.strip()
                    })

    def analyze_ssh(self, line):
        fail_match = re.search(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)', line)
        if fail_match:
            ip = fail_match.group(1)
            self.ip_counts[ip] += 1
            if self.ip_counts[ip] >= self.error_thresh:
                self.flagged_requests.append({
                    "ip": ip,
                    "reason": "Multiple failed SSH login attempts",
                    "line": line.strip()
                })

    def summarize(self):
        summary = {
            "high_request_ips": [ip for ip, count in self.ip_counts.items() if count >= self.request_thresh],
            "high_404_ips": [ip for ip, count in self.ip_404_counts.items() if count >= self.error_thresh],
            "suspicious_events": self.flagged_requests
        }
        return summary


def main():
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious activity.")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("--type", choices=["apache", "ssh"], required=True, help="Type of log file")
    parser.add_argument("--request-threshold", type=int, default=50, help="Threshold for request count")
    parser.add_argument("--error-threshold", type=int, default=10, help="Threshold for 404 errors or SSH failures")
    args = parser.parse_args()

    analyzer = LogAnalyzer(args.type, args.request_threshold, args.error_threshold)

    try:
        with open(args.logfile, "r") as f:
            for line in f:
                analyzer.analyze_line(line)

        output = analyzer.summarize()
        with open("suspicious_summary.json", "w") as out_file:
            json.dump(output, out_file, indent=4)

        print("Analysis complete. Output saved to suspicious_summary.json")

    except FileNotFoundError:
        print("Log file not found:", args.logfile)


if __name__ == "__main__":
    main()
