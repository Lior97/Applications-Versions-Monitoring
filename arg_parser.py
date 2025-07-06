#!/usr/bin/env python3

import argparse

def get_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for version check scripts.

    Returns:
        Configured ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Check application or OS versions")
    parser.add_argument('--github-token', help="GitHub API token")
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                        help="Set logging level (default: INFO)")
    parser.add_argument('--type', choices=['APPS', 'OS', 'CWM'], required=True,
                        help="Type of version check to perform (APPS, OS, or CWM)")
    return parser
