# Log-Analyzer
Suspicious Log Analyzer is a Python-based tool designed to detect potentially malicious behavior in server logs, specifically Apache access logs and SSH authentication logs. It flags indicators such as repeated failed login attempts, excessive 404 errors, high request volume from a single IP, and suspicious user agents often associated with automated scanners like curl, sqlmap, or nikto.

The analyzer supports both JSON and CSV output formats, with timestamped filenames for easy tracking. It includes a command-line interface for specifying the log type, request and error thresholds, and output format. The terminal output is color-coded for readability and provides a quick summary of suspicious events and the IPs involved.

This project was built as part of my cybersecurity development journey to demonstrate practical skills in log analysis, threat detection, and Python CLI tool design. It serves as a solid foundation for further enhancements such as IP geolocation, visual dashboards, or threat intelligence API integrations. The codebase is structured to be easily extendable to support additional log formats and detection rules.
