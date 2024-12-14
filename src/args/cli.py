from src.log import logger
from argparse import (
    ArgumentParser,
    Namespace,
)


def parse_arguments() -> Namespace:
    description = 'A simple command-line interface for CxSAST in Python.'
    parser = ArgumentParser(description=description)
    parser.add_argument('scan')
    parser.add_argument('--cxone_access_control_url', required=True, help="CxOne iam url")
    parser.add_argument('--cxone_server', required=True, help="CxOne server url")
    parser.add_argument('--cxone_tenant_name', required=True, help="CxOne tenant name")
    parser.add_argument('--cxone_grant_type', required=True, help="CxOne grant type, refresh_token")
    parser.add_argument('--cxone_refresh_token', required=True, help="CxOne API Key")
    parser.add_argument('--preset', required=True, help="The preset (rule set) name")
    parser.add_argument('--incremental', help="Set it True for incremental scan")
    parser.add_argument('--location_path', required=True, help="Source code folder absolute path")
    parser.add_argument('--project_name', required=True, help="Checkmarx project name")
    parser.add_argument('--branch', required=True, help="git repo branch to scan")
    parser.add_argument('--scanners', default="sast,sca,kics,apisec,containers,microengines",
                        help="scanners: sast,sca,kics,apisec,containers,microengines")
    parser.add_argument('--exclude_folders', help="exclude folders")
    parser.add_argument('--exclude_files', help='exclude files')
    parser.add_argument('--report_csv', default=None, help="csv report file path")
    parser.add_argument('--full_scan_cycle', default=10,
                        help="Defines the number of incremental scans to be performed, before performing a periodic "
                             "full scan")
    parser.add_argument('--cxone_proxy', help="proxy URL")
    parser.add_argument('--scan_tag_key', help="tag key, multiple keys can use comma separated value")
    parser.add_argument('--scan_tag_value', help="tag value, multiple keys can use comma separated value")
    parser.add_argument('--parallel_scan_cancel', default="false", help="enable parallel scan cancel")
    parser.add_argument('--scan_commit_number', default=0,
                        help="number of commit to trigger new scan. every commit to trigger new scan would flush CxOne"
                        )
    parser.add_argument('--sca_exploitable_path', default="false",
                        help="enable SCA exploitable path or not"
                        )
    parser.add_argument('--sca_last_sast_scan_time', default=2,
                        help="use sast scan from last n days, default to 2"
                        )
    return parser.parse_known_args()[0]


def process_arguments(arguments: Namespace) -> tuple:
    cxone_access_control_url = arguments.cxone_access_control_url
    cxone_server = arguments.cxone_server
    cxone_tenant_name = arguments.cxone_tenant_name
    cxone_grant_type = arguments.cxone_grant_type
    cxone_proxy = arguments.cxone_proxy
    preset = arguments.preset
    incremental = False if arguments.incremental.lower() == "false" else True
    location_path = arguments.location_path
    branch = arguments.branch
    exclude_folders = arguments.exclude_folders
    exclude_files = arguments.exclude_files
    report_csv = arguments.report_csv
    full_scan_cycle = int(arguments.full_scan_cycle)
    scanners = [scanner for scanner in arguments.scanners.split(",")]
    scan_tag_key = [key for key in arguments.scan_tag_key.split(",")] if arguments.scan_tag_key else None
    scan_tag_value = [value for value in arguments.scan_tag_value.split(",")] if arguments.scan_tag_value else None
    project_path_list = arguments.project_name.split("/")
    project_name = project_path_list[-1]
    group_full_name = "/".join(project_path_list[0: len(project_path_list) - 1])
    parallel_scan_cancel = False if arguments.parallel_scan_cancel.lower() == "false" else True
    scan_commit_number = int(arguments.scan_commit_number)
    sca_exploitable_path = False if arguments.sca_exploitable_path.lower() == "false" else True
    sca_last_sast_scan_time = int(arguments.sca_last_sast_scan_time)

    logger.info(
        f"cxone_access_control_url: {cxone_access_control_url}\n"
        f"cxone_server: {cxone_server}\n"
        f"cxone_tenant_name: {cxone_tenant_name}\n"
        f"cxone_grant_type: {cxone_grant_type}\n"
        f"cxone_proxy: {cxone_proxy}\n"
        f"preset: {preset}\n"
        f"incremental: {incremental}\n"
        f"location_path: {location_path}\n"
        f"branch: {branch}\n"
        f"exclude_folders: {exclude_folders}\n"
        f"exclude_files: {exclude_files}\n"
        f"report_csv: {report_csv}\n"
        f"full_scan_cycle: {full_scan_cycle}\n"
        f"scanners: {scanners}\n"
        f"scan_tag_key: {scan_tag_key}\n"
        f"scan_tag_value: {scan_tag_value}\n"
        f"project_name: {project_name}\n"
        f"group_full_name: {group_full_name}\n"
        f"parallel_scan_cancel: {parallel_scan_cancel}\n"
        f"scan_commit_number: {scan_commit_number}\n"
        f"sca_exploitable_path: {sca_exploitable_path}\n"
        f"sca_last_sast_scan_time: {sca_last_sast_scan_time}\n"
    )
    return (
        cxone_server, cxone_tenant_name, preset, incremental, location_path, branch, exclude_folders, exclude_files,
        report_csv, full_scan_cycle, scanners, scan_tag_key, scan_tag_value, project_name, group_full_name,
        parallel_scan_cancel, scan_commit_number, sca_exploitable_path, sca_last_sast_scan_time
    )


def get_command_line_arguments() -> tuple:
    """

    Returns:
        Namespace
    """
    arguments = parse_arguments()
    return process_arguments(arguments)
