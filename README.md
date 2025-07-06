# Version Monitoring Pipeline

A Jenkins pipeline to monitor and report outdated software versions for applications and operating systems, using GitHub APIs and web scraping. Generates CSV reports and sends Zulip notifications.

---

## Table of Contents

- [Overview](#overview)  
- [Features](#features)  
- [Prerequisites](#prerequisites)  

---

## Overview

This project automates version monitoring for applications (APPS), operating systems (OS), and custom web applications (CWM). It compares configured versions against the latest versions from GitHub or official websites, saves results in a CSV file, and sends notifications via Zulip.

---

## Features

- **Version Comparison**: Checks current vs. latest versions from GitHub or web sources.  
- **TOML Configuration**: Defines monitored software in TOML files.  
- **Zulip Notifications**: Sends formatted version status tables to Zulip.  
- **Error Handling**: Manages invalid versions, network issues, and API rate limits.  
- **Flexible Checks**: Supports APPS, OS, and CWM version checks.  

---

## Prerequisites

- **Jenkins**: Server with `Images` agent label.  
- **Python 3**: For running version check scripts.  
- **Git**: For repository cloning.  
- **Zulip**: Configured with `Utilities/Zuliip-Notification` job.  
- **GitHub Token**: API token with repo read access (Jenkins credential ID: `github-token2`).  
- **Python Packages**:
  ```bash
  pip install toml requests packaging beautifulsoup4
