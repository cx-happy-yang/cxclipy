curl -LO https://github.com/HappyY19/cxclipy/releases/download/v0.8.2/CxCliPy
ls -lah
chmod +x ./CxCliPy
source ~/.secrets

# Test flow without --branch_project (local ZIP upload)
./CxCliPy scan \
--cxsast_base_url https://192.168.3.3 \
--cxsast_username $CXSAST_USERNAME \
--cxsast_password $CXSAST_PASSWORD \
--cxsast_verify /mnt/d/Downloads/DESKTOP-RMVPBOC.crt \
--preset All \
--incremental False \
--location_type Folder \
--location_path /home/happy/JavaVulnerableLab \
--project_name /CxServer/jvl_git \
--exclude_folders "test,integrationtest" \
--exclude_files "*min.js" \
--report_xml cx-report-without-branch.xml \
--filter_severity "Critical,High,Medium" \
--full_scan_cycle 10 \
--cxsast_timeout 300

# Test flow with --branch_project (upload ZIP to branched project)
./CxCliPy scan \
--cxsast_base_url https://192.168.3.3 \
--cxsast_username $CXSAST_USERNAME \
--cxsast_password $CXSAST_PASSWORD \
--cxsast_verify /mnt/d/Downloads/DESKTOP-RMVPBOC.crt \
--preset All \
--incremental False \
--location_type Folder \
--location_path /home/happy/JavaVulnerableLab \
--project_name /CxServer/jvl_git \
--exclude_folders "test,integrationtest" \
--exclude_files "*min.js" \
--report_xml cx-report-with-branch.xml \
--filter_severity "Critical,High,Medium" \
--full_scan_cycle 10 \
--cxsast_timeout 300 \
--branch_project my-branched-project
