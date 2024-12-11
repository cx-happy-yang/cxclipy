from args import get_command_line_arguments
from cx import (
    get_or_create_groups,
    process_project,
    should_create_new_scan,
    cx_scan_from_local_zip_file,
    generate_sast_report,
    upload_zip_file,
    show_scan_statistics,
    get_a_list_of_scans,
    check_sast_scan_type,
    check_scanners,
)
from zip import create_zip_file_from_location_path, delete_zip_file
from git import get_git_commit_history


def run_scan_and_generate_reports():
    (
        cxone_server, cxone_tenant_name, preset, sast_incremental, location_path, branch, exclude_folders,
        exclude_files,
        report_csv, full_scan_cycle, scanners, scan_tag_key, scan_tag_value, project_name, group_full_name,
        parallel_scan_cancel, scan_commit_number, sca_exploitable_path, sca_last_sast_scan_time
    ) = get_command_line_arguments()
    group_ids = get_or_create_groups(
        group_full_name=group_full_name,
        cxone_tenant_name=cxone_tenant_name
    )
    project_id = process_project(
        project_name=project_name,
        group_ids=group_ids,
        sca_last_sast_scan_time=sca_last_sast_scan_time
    )
    zip_file_path, sha_256_hash = create_zip_file_from_location_path(
        location_path_str=location_path,
        project_id=project_id,
        exclude_folders_str=exclude_folders,
        exclude_files_str=exclude_files
    )
    git_commit_history = get_git_commit_history(location_path=location_path)
    scan_collection = get_a_list_of_scans(
        offset=0,
        limit=1024,
        project_id=project_id,
        branch=branch,
        sort=["+created_at"]
    )
    if not should_create_new_scan(
            zip_file_path=zip_file_path,
            scan_collection=scan_collection,
            sha_256_hash=sha_256_hash,
            scan_commit_number=scan_commit_number,
            git_commit_history=git_commit_history,
            parallel_scan_cancel=parallel_scan_cancel,
    ):
        return
    upload_url = upload_zip_file(zip_file_path=zip_file_path)
    delete_zip_file(zip_file_path=zip_file_path)
    sast_incremental = check_sast_scan_type(
        scan_collection=scan_collection,
        full_scan_cycle=full_scan_cycle,
        sast_incremental=sast_incremental,
    )
    scanners = check_scanners(
        scanners=scanners,
        scan_collection=scan_collection,
        sca_last_sast_scan_time=sca_last_sast_scan_time,
    )
    scan_id = cx_scan_from_local_zip_file(
        preset=preset,
        project_id=project_id,
        branch=branch,
        sha_256_hash=sha_256_hash,
        upload_url=upload_url,
        sast_incremental=sast_incremental,
        scanners=scanners,
        sca_exploitable_path=sca_exploitable_path,
        sca_last_sast_scan_time=sca_last_sast_scan_time,
        git_commit_history=git_commit_history,
        scan_tag_key=scan_tag_key,
        scan_tag_value=scan_tag_value,
    )
    show_scan_statistics(
        scanners=scanners,
        scan_id=scan_id
    )
    if "sast" in scanners:
        generate_sast_report(
            cxone_server=cxone_server,
            project_id=project_id,
            scan_id=scan_id,
            report_file_path=report_csv
        )


if __name__ == '__main__':
    run_scan_and_generate_reports()
