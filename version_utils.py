#!/usr/bin/env python3

import toml
import requests
import csv
import re
from packaging.version import parse, InvalidVersion
from bs4 import BeautifulSoup
from typing import Dict, Optional, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from enum import Enum

# Log level enumeration
class LogLevel(Enum):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

# Global constants
WEB_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 5
MAX_RETRIES = 3
BACKOFF_FACTOR = 1

# Version patterns
VERSION_PATTERNS = {
    'github': [
        r'(\d+\.\d+\.\d+\.\d+)',  # e.g., 1.2.3.4
        r'(\d+\.\d+\.\d+(?:[\w-]*\b)?)',  # e.g., 1.2.3, 1.2.3-rc1
        r'(\d+\.\d+(?:[\w-]*\b)?)',  # e.g., 1.2, 1.2-rc1
        r'v(\d+\.\d+\.\d+(?:[\w-]*\b)?)',  # e.g., v2.12.3
        r'release-(\d{4}-\d{2}-\d{2}[a-z]?)',  # e.g., release-2024-02-06b
        r'stable/jitsi-meet_(\d+)',  # e.g., stable/jitsi-meet_10184
    ],
    'general': [
        r'v(\d+\.\d+\.\d+(?:[\w-]*\b)?)',  # e.g., v8.3.1
        r'(\d+\.\d+\.\d+\.\d+)',  # e.g., 1.2.3.4
        r'(\d+\.\d+\.\d+(?:[\w-]*\b)?)',  # e.g., 1.2.3
        r'(\d+\.\d+(?:[\w-]*\b)?)',  # e.g., 1.2
        r'Version\s+(\d+\.\d+\.\d+(?:[\w-]*\b)?)',  # e.g., Version 8.3.1
    ],
   'ubuntu': [r'(\d{2}\.\d{2})\s+LTS'], # e.g., "20.04 LTS"
   'debian': [r'Debian\s+(\d+)(?:\.\d+)?(?:\s*\("[\w-]+"\))?'],  # e.g., "Debian 12 (bookworm)"
   'centos': [
        r'(?:CentOS\s+Stream\s+|Stream\s+)(\d+)',  # e.g., "CentOS Stream 10"
        r'(\d+)\s*(?:Stream|CentOS)',  # e.g., "10 Stream"
    ],
    'almalinux': [r'(\d+\.\d+)'],  # e.g., "9.2"
    'rockylinux': [r'(\d+\.\d+)'],  # e.g., "8.5"
    'linuxmint': [r'Linux\s+Mint\s+(\d+\.\d+)'],  # e.g., "Linux Mint 21.1"
    'windows-desktop': [
    r'Windows\s+(\d+(?:\.\d+)?)'],  # Windows 10, Windows 11
    'windows-server': [
    r'Windows\s+Server\s+(\d{4})'],  # Windows Server 2022, 2025
}

def log(message: str, level: LogLevel = LogLevel.DEBUG, log_level: LogLevel = LogLevel.INFO) -> None:
    """Log a message if the log level is sufficient.

    Args:
        message: The message to log.
        level: The log level.
        log_level: The configured log level threshold.
    """
    if level.value >= log_level.value:
        print(f"[{level.name}] {message}")

def load_config(config_file: str, log_level: LogLevel = LogLevel.INFO) -> Dict:
    """Load and validate the TOML configuration file.

    Args:
        config_file: Path to the TOML file.
        log_level: Configured log level.

    Returns:
        A dictionary with the TOML content.

    Raises:
        RuntimeError: If the config file cannot be loaded or is invalid.
    """
    log(f"Loading config file: {config_file}", LogLevel.INFO, log_level)
    try:
        with open(config_file, 'r') as f:
            data = toml.load(f)
        # Validate required fields
        for app, info in data.items():
            if 'version' not in info:
                raise ValueError(f"Missing 'version' for {app}")
            if 'repo' not in info and 'version_url' not in info:
                raise ValueError(f"Missing 'repo' or 'version_url' for {app}")
            # Validate version format
            try:
                parse(info['version'])
            except InvalidVersion as e:
                raise ValueError(f"Invalid version format for {app}: {info['version']} ({e})")
        log(f"Successfully loaded config: {data}", LogLevel.DEBUG, log_level)
        return data
    except (toml.TomlDecodeError, FileNotFoundError, ValueError) as e:
        log(f"Error loading config: {e}", LogLevel.ERROR, log_level)
        raise RuntimeError(f"Failed to load config file '{config_file}': {e}")

def extract_version_with_patterns(text: str, patterns: List[str], ignore_case: bool = False, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract a version number from the text using the provided regex patterns.

    Args:
        text: The text to search.
        patterns: List of regex patterns to match.
        ignore_case: Whether to perform a case-insensitive match.
        log_level: Configured log level.

    Returns:
        The extracted version string, or None if no match is found.
    """
    log(f"Extracting version from text: {text[:50]}...", LogLevel.DEBUG, log_level)
    flags = re.IGNORECASE if ignore_case else 0
    for pattern in patterns:
        match = re.search(pattern, text, flags)
        if match:
            version = match.group(1)
            if log_level == LogLevel.DEBUG:
                log(f"Found version with pattern {pattern}: {version}", LogLevel.DEBUG, log_level)
            return version
    log("No version found with provided patterns", LogLevel.DEBUG, log_level)
    return None

def parse_and_validate_version(version: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Parse and validate a version string, appending .0 for single-digit versions if needed.

    Args:
        version: The version string to parse.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The validated version string, or None if invalid.
    """
    log(f"Validating version for {app}: {version}", LogLevel.DEBUG, log_level)
    try:
        parsed = parse(version)
        if not hasattr(parsed, 'minor'):
            version = f"{version}.0"
            parsed = parse(version)
            log(f"Appended .0 to version: {version}", LogLevel.DEBUG, log_level)
        return version
    except InvalidVersion as e:
        log(f"Invalid version for {app}: {version} ({e})", LogLevel.ERROR, log_level)
        return None

def sort_versions(version_candidates: List[str], app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Sort and validate version candidates, returning the latest valid version.

    Args:
        version_candidates: List of version strings.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The latest valid version, or "Unknown" if none are valid.
    """
    log(f"Sorting versions for {app}: {version_candidates}", LogLevel.DEBUG, log_level)
    if not version_candidates:
        log(f"No version candidates found for {app}", LogLevel.WARNING, log_level)
        return "Unknown"

    def version_key(v: str) -> tuple:
        try:
            parsed = parse(v)
            if not hasattr(parsed, 'minor'):
                return (1, v)
            return (0, parsed)
        except (InvalidVersion, ValueError):
            return (1, v)

    version_candidates.sort(key=version_key, reverse=True)
    if version_key(version_candidates[0])[0] == 1:
        log(f"No valid version candidates found for {app}", LogLevel.ERROR, log_level)
        return "Unknown"
    latest_version = version_candidates[0]
    log(f"Selected latest version for {app}: {latest_version}", LogLevel.INFO, log_level)
    return latest_version

def parse_version_from_github_tag(tag_name: str, release_name: Optional[str] = None, patterns: Optional[List[str]] = None, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Parse a version number from a GitHub tag or release name.

    Args:
        tag_name: The GitHub tag name.
        release_name: The GitHub release name (optional).
        patterns: List of regex patterns to match (optional).
        log_level: Configured log level.

    Returns:
        The extracted version string, or None if no match is found.
    """
    log(f"Extracting version from tag: {tag_name}, release name: {release_name}", LogLevel.DEBUG, log_level)
    patterns = patterns or VERSION_PATTERNS['github']

    if release_name:
        version = extract_version_with_patterns(release_name, patterns, log_level=log_level)
        if version:
            return version

    version = extract_version_with_patterns(tag_name, patterns, log_level=log_level)
    if version:
        return version

    if tag_name.startswith('v') and re.match(r'v\d+\.\d+(?:\.\d+)?', tag_name):
        version = tag_name[1:]
        log(f"Fallback extracted version: {version}", LogLevel.DEBUG, log_level)
        return version

    log(f"No version number found in tag: {tag_name}", LogLevel.WARNING, log_level)
    return None

def github_latest_versions(repo: str, github_token: Optional[str] = None, skip_prerelease: bool = False, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Fetch the latest version from a GitHub repository, trying releases first, then tags.

    Args:
        repo: The GitHub repository (e.g., "owner/repo").
        github_token: GitHub API token (optional).
        skip_prerelease: Whether to skip pre-release versions.
        log_level: Configured log level.

    Returns:
        The latest version string, or "Unknown" if not found.
    """
    headers = {'Authorization': f'token {github_token}'} if github_token else {}
    # Try releases first
    releases_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        log(f"Fetching releases from {releases_url}", LogLevel.INFO, log_level)
        response = requests.get(releases_url, headers=headers, timeout=REQUEST_TIMEOUT)
        log(f"Releases API response status for {repo}: {response.status_code}", LogLevel.DEBUG, log_level)
        response.raise_for_status()
        release_data = response.json()
        raw_tag = release_data['tag_name']
        release_name = release_data.get('name', '')
        log(f"Release tag for {repo}: {raw_tag}, release name: {release_name}", LogLevel.DEBUG, log_level)
        version = parse_version_from_github_tag(raw_tag, release_name, log_level=log_level)
        # Apply Arch Linux cleaning if the repo indicates Arch Linux
        if "archlinux" in repo.lower() and version:
            version = handle_archlinux(version, log_level=log_level)
        # Apply DokuWiki cleaning if the repo indicates DokuWiki
        if "dokuwiki" in repo.lower() and version:
            version = handle_dokuwiki(version, log_level=log_level)
        # If version is still not found and DokuWiki, try release name directly
        if "dokuwiki" in repo.lower() and not version and release_name:
            version = handle_dokuwiki(release_name, log_level=log_level)
        if version:  # Ensure version is valid before returning
            parsed_version = parse_and_validate_version(version, repo, log_level)
            return parsed_version if parsed_version else "Unknown"
        return "Unknown"
    except requests.RequestException as e:
        log(f"No releases found for {repo}: {e}. Trying tags...", LogLevel.WARNING, log_level)

    # Fall back to tags
    tags_url = f"https://api.github.com/repos/{repo}/tags"
    try:
        session = requests.Session()
        retries = Retry(total=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        log(f"Fetching tags from {tags_url}", LogLevel.INFO, log_level)
        response = session.get(tags_url, headers=headers, timeout=REQUEST_TIMEOUT)
        log(f"Tags API response status for {repo}: {response.status_code}", LogLevel.DEBUG, log_level)
        response.raise_for_status()
        tags = response.json()
        if not tags:
            log(f"No tags found for {repo}", LogLevel.WARNING, log_level)
            return "Unknown"

        version_tags = []
        for tag in tags:
            raw_tag = tag['name']
            if raw_tag.startswith('archive/'):
                log(f"Skipping archive tag for {repo}: {raw_tag}", LogLevel.DEBUG, log_level)
                continue
            log(f"Checking tag for {repo}: {raw_tag}", LogLevel.DEBUG, log_level)
            version = parse_version_from_github_tag(raw_tag, log_level=log_level)
            if version:
                # Apply Arch Linux cleaning if the repo indicates Arch Linux
                if "archlinux" in repo.lower():
                    version = handle_archlinux(version, log_level=log_level)
                # Apply DokuWiki cleaning if the repo indicates DokuWiki
                if "dokuwiki" in repo.lower():
                    version = handle_dokuwiki(version, log_level=log_level)
                if version:  # Ensure version is valid before parsing
                    parsed_version = parse_and_validate_version(version, repo, log_level)
                    if parsed_version:
                        if skip_prerelease and parse(parsed_version).is_prerelease:
                            log(f"Skipping pre-release version: {version}", LogLevel.DEBUG, log_level)
                            continue
                        version_tags.append(parsed_version)
        return sort_versions(version_tags, repo, log_level) if version_tags else "Unknown"
    except requests.RequestException as e:
        log(f"Error fetching tags for {repo}: {e}", LogLevel.ERROR, log_level)
        return "Unknown"

def fetch_web_content(url: str, log_level: LogLevel = LogLevel.INFO) -> Optional[BeautifulSoup]:
    """Fetch and parse the content of a web page using BeautifulSoup with retries.

    Args:
        url: The URL to fetch.
        log_level: Configured log level.

    Returns:
        A BeautifulSoup object with the parsed HTML, or None if the request fails.
    """
    session = requests.Session()
    retries = Retry(total=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    log(f"Fetching {url} with requests", LogLevel.INFO, log_level)
    try:
        response = session.get(url, headers=WEB_HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        log(f"Successfully fetched {url}, status: {response.status_code}", LogLevel.DEBUG, log_level)
        return BeautifulSoup(response.text, 'html.parser')
    except requests.RequestException as e:
        log(f"Error fetching {url}: {e}", LogLevel.ERROR, log_level)
        return None

def handle_windows_server(text: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract Windows Server year version from text.

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The extracted year version string (e.g., "2025"), or None if not found.
    """
    log(f"Checking Windows Server version in text: {text[:50]}...", LogLevel.DEBUG, log_level)

    # Extract only the year version
    year_match = re.search(r'Windows\s+Server\s+(\d{4})', text, re.IGNORECASE)
    if year_match:
        year_version = year_match.group(1)
        log(f"Found Windows Server year version: {year_version}", LogLevel.INFO, log_level)
        return year_version

    log("No Windows Server year version found in text", LogLevel.DEBUG, log_level)
    return None

def handle_windows_desktop(text: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract Windows version from text.

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The extracted version string, or None if not found.
    """
    log(f"Checking Windows version in text: {text[:50]}...", LogLevel.DEBUG, log_level)

    # Try to extract Windows version number
    patterns = VERSION_PATTERNS.get('windows-desktop', [])
    version = extract_version_with_patterns(text, patterns, ignore_case=True, log_level=log_level)

    if version:
        # For Windows, we want to keep numeric versions (like 10, 11)
        # and special format versions (like 22H2)
        if re.match(r'\d+(?:\.\d+)?', version) or re.match(r'\d{2}H\d', version):
            parsed_version = parse_and_validate_version(version, app, log_level)
            if parsed_version:
                log(f"Found Windows version: {parsed_version}", LogLevel.INFO, log_level)
                return parsed_version

    log("No Windows version found in text", LogLevel.DEBUG, log_level)
    return None

def handle_dokuwiki(version: Optional[str], app: str = "DokuWiki", log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract DokuWiki version number from within square brackets [ ].

    Args:
        version: The version string to process (e.g., "DokuWiki 2025-05-14 'Librarian' [56]"), or None.
        app: The application name (for logging), defaults to "DokuWiki".
        log_level: Configured log level.

    Returns:
        The extracted version number (e.g., "56"), or None if invalid or input is None.
    """
    if version is None:
        log(f"Received None version for DokuWiki, skipping cleaning for {app}", LogLevel.WARNING, log_level)
        return None
    log(f"Checking DokuWiki version: {version}", LogLevel.DEBUG, log_level)
    match = re.search(r'\[(\d+(?:\.\d+)?)\]', version)
    if match:
        extracted_version = match.group(1)
        log(f"Extracted DokuWiki version from [ ] for {app}: {extracted_version}", LogLevel.DEBUG, log_level)
        parsed_version = parse_and_validate_version(extracted_version, app, log_level)
        if parsed_version:
            return parsed_version
    log(f"Failed to parse DokuWiki version from [ ]: {version}", LogLevel.WARNING, log_level)
    return None

def handle_archlinux(version: Optional[str], app: str = "archlinux", log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract and clean Arch Linux version by stripping -archN suffix.

    Args:
        version: The version string to process (e.g., "6.14.7-arch1"), or None.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The cleaned version string (e.g., "6.14.7"), or None if invalid or input is None.
    """
    if version is None:
        log(f"Received None version for Arch Linux, skipping cleaning for {app}", LogLevel.WARNING, log_level)
        return None
    log(f"Checking Arch Linux version: {version}", LogLevel.DEBUG, log_level)
    match = re.search(r'(\d+\.\d+\.\d+)(?:[-]arch\d+)?', version)
    if match:
        cleaned_version = match.group(1)
        log(f"Cleaned Arch Linux version for {app}: {cleaned_version}", LogLevel.DEBUG, log_level)
        parsed_version = parse_and_validate_version(cleaned_version, app, log_level)
        if parsed_version:
            return parsed_version
    log(f"Failed to parse Arch Linux version: {version}", LogLevel.WARNING, log_level)
    return None

def handle_odoo(text: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract Odoo version (major version only).

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The major version string (e.g., "18" from "Odoo 18.0"), or None if not found.
    """
    log(f"Checking Odoo version in text: {text[:50]}...", LogLevel.DEBUG, log_level)
    match = re.search(r'Odoo\s+(?!SaaS)(\d+\.\d+)', text)
    if match:
        version = match.group(1)
        parsed_version = parse_and_validate_version(version, app, log_level)
        if parsed_version:
            major_version = parsed_version.split('.')[0]
            log(f"Found Odoo version: {major_version} (from {version})", LogLevel.INFO, log_level)
            return major_version
    log("No Odoo version found", LogLevel.WARNING, log_level)
    return None

def handle_postgresql(text: str, app: str, log_level: LogLevel = LogLevel.INFO, current_major: Optional[str] = None) -> Optional[Dict]:
    """Extract PostgreSQL version from announcements or sidebar.

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.
        current_major: The current major version (for sidebar parsing), if any.

    Returns:
        A dictionary with 'version' (the extracted version) and 'current_major' (updated major version),
        or None if no version is found.
    """
    log(f"Checking PostgreSQL version in text: {text[:50]}...", LogLevel.DEBUG, log_level)
    # Announcement: e.g., "PostgreSQL 17.4, 16.8 Released!"
    match = re.search(r'(?:\w+\s+\d{1,2},\s+\d{4}:\s*)?PostgreSQL\s+(\d+\.\d+)(?:,\s*\d+\.\d+)*(?:\s*and\s*\d+\.\d+)?\s*Released!', text)
    if match:
        versions_text = text
        version_candidates = []
        for version_match in re.finditer(r'(\d+\.\d+)', versions_text):
            version = version_match.group(1)
            parsed_version = parse_and_validate_version(version, app, log_level)
            if parsed_version:
                version_candidates.append(parsed_version)
                log(f"Found PostgreSQL version (announcement): {parsed_version}", LogLevel.INFO, log_level)
        latest_version = sort_versions(version_candidates, app, log_level) if version_candidates else None
        return {'version': latest_version, 'current_major': current_major}

    # Sidebar: e.g., "PostgreSQL 17" followed by "17.4"
    major_match = re.search(r'PostgreSQL\s+(\d+)', text)
    if major_match:
        current_major = major_match.group(1)
        log(f"Detected PostgreSQL major version: {current_major}", LogLevel.DEBUG, log_level)
        return {'version': None, 'current_major': current_major}

    if current_major:
        minor_match = re.search(rf'{current_major}\.(\d+)', text)
        if minor_match:
            version = f"{current_major}.{minor_match.group(1)}"
            parsed_version = parse_and_validate_version(version, app, log_level)
            if parsed_version:
                log(f"Found PostgreSQL version (sidebar): {parsed_version}", LogLevel.INFO, log_level)
                return {'version': parsed_version, 'current_major': current_major}

    log("No PostgreSQL version found", LogLevel.WARNING, log_level)
    return {'version': None, 'current_major': current_major}

def handle_plesk(text: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract Plesk PSA version.

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The extracted version string, or None if not found.
    """
    log(f"Checking Plesk version in text: {text[:50]}...", LogLevel.DEBUG, log_level)
    match = re.search(r'PSA_(\d+\.\d+\.\d+)', text)
    if match:
        version = match.group(1)
        parsed_version = parse_and_validate_version(version, app, log_level)
        if parsed_version:
            log(f"Found Plesk PSA version: {parsed_version}", LogLevel.INFO, log_level)
            return parsed_version
    log("No Plesk version found", LogLevel.WARNING, log_level)
    return None

def handle_clustercontrol(text: str, app: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract ClusterControl version from package names.

    Args:
        text: The text to search.
        app: The application name (for logging).
        log_level: Configured log level.

    Returns:
        The extracted version string, or None if not found.
    """
    log(f"Checking ClusterControl version in text: {text[:50]}...", LogLevel.DEBUG, log_level)
    match = re.search(r'clustercontrol(?:-controller)?-(\d+\.\d+\.\d+)(?:-\d+)?(?:-x86_64|-i386)?(?:\.rpm|\.deb)', text)
    if match:
        version = match.group(1)
        parsed_version = parse_and_validate_version(version, app, log_level)
        if parsed_version:
            log(f"Found ClusterControl version: {parsed_version}", LogLevel.INFO, log_level)
            return parsed_version
    log("No ClusterControl version found", LogLevel.WARNING, log_level)
    return None

def extract_version_from_web(app: str, url: str, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Extract the latest version number from a web page with app-specific logic.

    Args:
        app: The application or OS name.
        url: The URL to scrape.
        log_level: Configured log level.

    Returns:
        The latest version string, or "Unknown" if not found.
    """
    log(f"Extracting version from web for {app}: {url}", LogLevel.INFO, log_level)
    soup = fetch_web_content(url, log_level)
    if not soup:
        log(f"Failed to fetch web content for {app}", LogLevel.ERROR, log_level)
        return "Unknown"

    version_candidates = []
    app_patterns = VERSION_PATTERNS.get(app.lower(), VERSION_PATTERNS.get('general', []))
    log(f"Using patterns for {app}: {app_patterns}", LogLevel.DEBUG, log_level)
    current_major = None  # For PostgreSQL sidebar parsing

    # App-specific extraction logic
    app_extractors = {
        'odoo': handle_odoo,
        'postgresql': handle_postgresql,
        'plesk': handle_plesk,
        'clustercontrol': handle_clustercontrol,
        'windows-desktop': handle_windows_desktop,
        'windows-server': handle_windows_server,
    }

    for tag in soup.find_all(['h1', 'h2', 'h3', 'p', 'span', 'div', 'li', 'a', 'td', 'th']):
        text = tag.get_text(strip=True)
        log(f"Checking tag {tag.name}: {text[:50]}", LogLevel.DEBUG, log_level)

        # Use app-specific extractor if available
        extractor = app_extractors.get(app.lower())
        if extractor:
            if app.lower() == 'postgresql':
                result = extractor(text, app, log_level, current_major)
                version = result['version']
                current_major = result['current_major']
            else:
                version = extractor(text, app, log_level)
            if version:
                version_candidates.append(version)
            continue

        if app.lower() != "ubuntu":
            # Generic pattern for the app: e.g., "app 1.2.3"
            match = re.search(rf'{app}\s*(\d+\.\d+(?:\.\d+)?(?:[\w-]*\b)?)', text, re.IGNORECASE)
            if match:
                version = match.group(1)
                parsed_version = parse_and_validate_version(version, app, log_level)
                if parsed_version:
                    version_candidates.append(parsed_version)
                    if log_level == LogLevel.DEBUG:
                        log(f"Found version in {tag.name}: {parsed_version}", LogLevel.INFO, log_level)
                continue

        # General patterns or OS-specific patterns
        version = extract_version_with_patterns(text, app_patterns, ignore_case=True, log_level=log_level)
        if version:
            parsed_version = parse_and_validate_version(version, app, log_level)
            if parsed_version:
                version_candidates.append(parsed_version)
                if log_level == LogLevel.DEBUG:
                    log(f"Found version in {tag.name}: {parsed_version}", LogLevel.INFO, log_level)

    return sort_versions(version_candidates, app, log_level)

def get_latest_version(app: str, app_info: Dict, github_token: Optional[str] = None, skip_prerelease: bool = False, log_level: LogLevel = LogLevel.INFO) -> Optional[str]:
    """Fetch the latest version, either from GitHub or a web URL.

    Args:
        app: The application or OS name.
        app_info: Dictionary with version source info (repo or version_url).
        github_token: GitHub API token (optional).
        skip_prerelease: Whether to skip pre-release versions.
        log_level: Configured log level.

    Returns:
        The latest version string, or "Unknown" if not found.
    """
    if 'repo' in app_info:
        log(f"Fetching version for {app} from GitHub", LogLevel.INFO, log_level)
        return github_latest_versions(app_info['repo'], github_token, skip_prerelease, log_level)
    elif 'version_url' in app_info:
        log(f"Fetching version for {app} from official website", LogLevel.INFO, log_level)
        return extract_version_from_web(app, app_info['version_url'], log_level)
    else:
        log(f"No repo or version_url provided for {app}", LogLevel.ERROR, log_level)
        return "Unknown"

def check_all_versions(config: Dict, github_token: Optional[str] = None, skip_prerelease: bool = False, log_level: LogLevel = LogLevel.INFO, type_filter: str = "all") -> List[Dict]:
    """Check the latest versions for all configured applications or OSes.

    Args:
        config: Loaded TOML configuration.
        github_token: GitHub API token (optional).
        skip_prerelease: Whether to skip pre-release versions.
        log_level: Configured log level.
        type_filter: Filter to process (e.g., "all", "App", "OS").

    Returns:
        List of dictionaries with current and latest versions.
    """
    app_status = []
    for app, app_info in config.items():
        if type_filter != "all" and (type_filter == "App" and app_info.get("type", "App").lower() != "app") or (type_filter == "OS" and app_info.get("type", "App").lower() != "os"):
            continue
        current_version = app_info.get("version", "Unknown")
        log(f"Checking {app} with current version: {current_version}", LogLevel.INFO, log_level)
        latest_version = get_latest_version(app, app_info, github_token, skip_prerelease, log_level)
        # Apply Arch Linux cleaning for OS entries
        if app.lower() == "archlinux" and latest_version:
            latest_version = handle_archlinux(latest_version, log_level=log_level)
        app_status.append({"OS" if app_info.get("type", "App").lower() == "os" else "App": app, "Current Version": current_version, "Latest Version": latest_version if latest_version else "Unknown"})
    return app_status

def save_artifact(data: List[Dict], filename: str, headers: List[str], log_level: LogLevel = LogLevel.INFO) -> None:
    """Save the version check results to a CSV file.

    Args:
        data: List of dictionaries containing version status.
        filename: Name of the output CSV file.
        headers: List of column headers.
        log_level: Configured log level.
    """
    log(f"Writing to CSV at: {filename}", LogLevel.INFO, log_level)
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for status in data:
            # Dynamically determine the key for the app/OS name
            app_key = next((key for key in status.keys() if key in ["OS", "App"]), None)
            if app_key:
                app_name = status[app_key]
                writer.writerow([app_name, status["Current Version"], status["Latest Version"]])
            else:
                log(f"Invalid status format: {status}", LogLevel.ERROR, log_level)
                writer.writerow(["Unknown", status.get("Current Version", "Unknown"), status.get("Latest Version", "Unknown")])
