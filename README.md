Version Monitoring Pipeline

A Jenkins pipeline to monitor and report outdated software versions for applications and operating systems, using GitHub APIs and web scraping. Generates CSV reports and sends Zulip notifications.
Table of Contents

Overview
Features
Prerequisites
Setup
Configuration
Usage
Pipeline Stages
Scripts and Files
Output
Contributing
License

Overview
This project automates version monitoring for applications (APPS), operating systems (OS), and custom web applications (CWM). It compares configured versions against the latest versions from GitHub or official websites, saves results in a CSV file, and sends notifications via Zulip.
Features

Version Comparison: Checks current vs. latest versions from GitHub or web sources.
TOML Configuration: Defines monitored software in TOML files.
Zulip Notifications: Sends formatted version status tables to Zulip.
Error Handling: Manages invalid versions, network issues, and API rate limits.
Flexible Checks: Supports APPS, OS, and CWM version checks.

Prerequisites

Jenkins: Server with Images agent label.
Python 3: For running version check scripts.
Git: For repository cloning.
Zulip: Configured with Utilities/Zuliip-Notification job.
GitHub Token: API token with repo read access (Jenkins credential ID: github-token2).
Python Packages:pip install toml requests packaging beautifulsoup4

Setup

Clone Repository:Configure Jenkins to clone https://git.cloudwm-dev.com/DevOps/versions-monitoring.git using Git-rndbot credentials.

Jenkins Configuration:

Add Jenkinsfile to your Jenkins setup.
Ensure Utilities/Zuliip-Notification job is set up for Zulip.
Store GitHub token in Jenkins as github-token2.


Install Python Dependencies:On the Images agent:
pip install toml requests packaging beautifulsoup4

View Output:

CSV report: versions-monitoring/outdated.csv
Zulip notifications: Jenkins stream, Version Updates topic

Access Artifacts:Archived CSV available in Jenkins.

Zulip Notification:
New versions detected for CWM:

| App/Service | CWM Version | Latest Version | Status |
|-------------|-------------|----------------|--------|
| gitea       | 1.23.5      | 1.23.8         | 🔴     |
| jenkins     | 2.492.3     | 2.510          | 🔴     |

Contributing

Fork the repository.
Create a feature branch: git checkout -b feature/YourFeature
Commit changes: git commit -m 'Add YourFeature'
Push: git push origin feature/YourFeature
Open a pull request.


