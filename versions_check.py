#!/usr/bin/env python3

from arg_parser import get_parser
from version_utils import load_config, check_all_versions, save_artifact, LogLevel

def main():
    """Main function to check application or OS versions based on type and generate an outdated versions report."""
    parser = get_parser()
    args = parser.parse_args()

    log_level = getattr(LogLevel, args.log_level)

    # Map type to TOML file and parameters
    config_map = {
        'APPS': {'file': 'installer_versions.toml', 'skip_prerelease': True, 'headers': ["App/Service", "CWM Version", "Latest Version"]},
        'OS': {'file': 'os_versions.toml', 'skip_prerelease': False, 'headers': ["OS", "Current Version", "Latest Version"]},
        'CWM': {'file': 'cwm_versions.toml', 'skip_prerelease': True, 'headers': ["App/Service", "CWM Version", "Latest Version"]}
    }

    if args.type not in config_map:
        raise ValueError(f"Invalid type: {args.type}. Must be 'APPS', 'OS', or 'CWM'.")

    config_info = config_map[args.type]
    config_file = config_info['file']
    skip_prerelease = config_info['skip_prerelease']
    headers = config_info['headers']

    config = load_config(config_file, log_level)
    app_status = check_all_versions(config, args.github_token, skip_prerelease=skip_prerelease, log_level=log_level)
    save_artifact(app_status, 'outdated.csv', headers, log_level)

if __name__ == "__main__":
    main()
