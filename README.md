Version Monitoring Pipeline

This project provides a Jenkins pipeline and associated Python scripts to monitor and report on outdated software versions for applications and operating systems, leveraging GitHub APIs and web scraping for version checks. The pipeline generates a CSV report of outdated versions and sends notifications via Zulip.

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

The Version Monitoring Pipeline automates the process of checking for outdated software versions by comparing configured versions against the latest versions available from GitHub repositories or official websites. It supports three types of checks: applications (APPS), operating systems (OS), and custom web applications (CWM). Results are saved in a CSV file and notifications are sent to a Zulip stream.

Features





Version Comparison: Compares configured versions with the latest versions from GitHub or web sources.



Flexible Configuration: Uses TOML files to define applications and OSes to monitor.



Automated Notifications: Sends detailed reports to Zulip with a formatted table of version statuses.



Robust Error Handling: Handles invalid versions, network issues, and API rate limits with retries.



Customizable Checks: Supports different types of version checks (APPS, OS, CWM) with configurable parameters.

Prerequisites





Jenkins: A Jenkins server with the Images agent label configured.



Python 3: Required for running the version check scripts.



Git: For cloning the repository.



Zulip: A Zulip instance for receiving notifications (requires a Jenkins job Utilities/Zuliip-Notification).



GitHub Token: A GitHub API token with repository read access for authenticated API calls.



Python Dependencies: Install required Python packages:

pip install toml requests packaging beautifulsoup4

Setup





Clone the Repository: Ensure the Jenkins pipeline can access the repository at https://git.cloudwm-dev.com/DevOps/versions-monitoring.git using the Git-rndbot credentials.



Configure Jenkins:





Add the provided Jenkinsfile to your Jenkins setup.



Ensure the Utilities/Zuliip-Notification job is configured to send notifications to your Zulip instance.



Store the GitHub API token in Jenkins credentials with ID github-token2.



Install Python Dependencies: On the Jenkins agent labeled Images, install the required Python packages:

pip install toml requests packaging beautifulsoup4



Prepare Configuration Files: Place the following TOML files in the versions-monitoring directory:





installer_versions.toml: For application versions.



os_versions.toml: For operating system versions.



cwm_versions.toml: For custom web application versions.

Configuration

The project uses TOML files to configure the versions to monitor. Each entry requires a version and either a repo (for GitHub) or version_url (for web scraping).





Example os_versions.toml:

[windows-server]
version = "2025"
version_url = "https://endoflife.date/windows-server"

[archlinux]
version = "6.14.4"
repo = "archlinux/linux"



Example cwm_versions.toml:

[gitea]
version = "1.24.2"
repo = "go-gitea/gitea"



Example installer_versions.toml:

[ansible]
version = "2.18.6"
repo = "ansible/ansible"

Usage





Run the Pipeline:





Trigger the Jenkins pipeline manually or via a schedule.



Select the TYPE parameter (APPS, OS, or CWM) to specify the type of version check.



Monitor Output:





The pipeline generates a CSV file (versions-monitoring/outdated.csv) with outdated version details.



Notifications are sent to the Zulip Jenkins stream under the Version Updates topic.



Check Artifacts:





The CSV file is archived as a Jenkins artifact for review.

Pipeline Stages





Clean Workspace: Clears the Jenkins workspace to ensure a fresh environment.



Cloning Repo: Clones the versions-monitoring repository from the specified Git URL.



Version Check: Runs the versions_check.py script to compare versions based on the selected TYPE.



Check Outdated Versions: Processes the CSV output, generates a formatted table, and triggers a Zulip notification.



Post Actions: Archives the CSV artifact and logs the pipeline status.

Scripts and Files





Jenkinsfile: Defines the Jenkins pipeline with stages for cloning, version checking, and notifications.



versions_check.py: Main script that orchestrates version checks based on the provided type.



arg_parser.py: Defines command-line arguments for the version check script.



version_utils.py: Contains utility functions for loading configurations, fetching versions, and saving results.



installer_versions.toml: Configuration for application versions.



os_versions.toml: Configuration for operating system versions.



cwm_versions.toml: Configuration for custom web application versions.



outdated.csv: Output file containing version comparison results.

