# VRV Security Python Internship Assignment

## Introduction

This repository contains a Python project developed as part of the internship assignment at VRV Security. The project focuses on analyzing server log files for security insights, including identifying suspicious activities, tracking IP addresses, and detecting failed login attempts. The goal of this project is to process and analyze server logs, extract meaningful insights, and help with security monitoring.

## Features

- **IP Address Request Count**: Analyzes the number of requests made by each IP address in the log files.
- **Most Accessed Endpoint**: Identifies the endpoint that has been accessed the most times.
- **Suspicious Activity Detection**: Detects suspicious activity based on failed login attempts (with a threshold set to 10 failed attempts).
- **Log Parsing**: Uses regular expressions to parse and extract data from Apache log format.
- **CSV Output**: Generates a CSV file with the results of the analysis, including IP addresses with the most requests, accessed endpoints, and IP addresses with failed login attempts exceeding the threshold.

## Installation

To run the project, make sure you have Python 3.x installed. You can install the required libraries using the following command:

```bash
pip install -r requirements.txt
