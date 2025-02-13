curl -LO https://github.com/HappyY19/cxclipy/releases/download/v0.4.3/CxOneCli
chmod +x ./CxOneCli
source ~/.secrets
# run sca scan
./CxOneCli scan \
--cxone_access_control_url https://sng.iam.checkmarx.net \
--cxone_server https://sng.ast.checkmarx.net \
--cxone_tenant_name happy  \
--cxone_grant_type refresh_token \
--cxone_refresh_token $CXONE_HAPPY_TOKEN \
--preset "ASA Premium"  \
--incremental true \
--location_path /mnt/d/HappyYang/Checkmarx/CxSCA/cx-results \
--project_name AlphaTeam/JavaVulnerableLab-2025-01-21 \
--exclude_folders "test,integrationtest" \
--exclude_files "*min.js" \
--report_csv cx-report.csv \
--full_scan_cycle 10  \
--scan_tag_key key1,key2 \
--scan_tag_value value1,value2 \
--parallel_scan_cancel true \
--scan_commit_number 1 \
--sca_exploitable_path false \
--branch master-sca \
--scanners sca \
--sca_last_sast_scan_time 2 \
--include_dot_git_folder true