curl -LO https://github.com/HappyY19/cxclipy/releases/download/v0.2.8/CxOneCli
chmod +x ./CxOneCli
source ~/.secrets
./CxOneCli scan \
--cxone_access_control_url https://sng.iam.checkmarx.net \
--cxone_server https://sng.ast.checkmarx.net \
--cxone_tenant_name happy  \
--cxone_grant_type refresh_token \
--cxone_refresh_token $CXONE_HAPPY_TOKEN \
--preset "ASA Premium"  \
--incremental false \
--location_path /mnt/e/github.com/CSPF-Founder/JavaVulnerableLab \
--project_name AlphaTeam/JavaVulnerableLab \
--branch master-sca \
--exclude_folders "test,integrationtest" \
--exclude_files "*min.js" \
--report_csv cx-report.csv \
--full_scan_cycle 10  \
--scan_tag_key branch,date \
--scan_tag_value master,2024-10-23 \
--parallel_scan_cancel true \
--scan_commit_number 0 \
--sca_exploitable_path true \
--scanners sast,sca