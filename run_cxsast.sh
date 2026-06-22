curl -LO https://github.com/HappyY19/cxclipy/releases/download/v0.7.0/CxCliPy
ls -lah
chmod +x ./CxCliPy
source ~/.secrets
# run scan
./CxCliPy scan \
--cxsast_base_url http://192.168.3.84 \
--cxsast_username $CXSAST_USERNAME \
--cxsast_password $CXSAST_PASSWORD \
--preset All \
--incremental False \
--location_type Folder \
--location_path /home/happy/Documents/JavaVulnerableLab \
--project_name /CxServer/happy-2022-11-21 \
--exclude_folders "test,integrationtest" \
--exclude_files "*min.js" \
--report_csv cx-report.csv \
--full_scan_cycle 10 \
--branch_project my-branched-project

# run other scans
# ./CxCliPy scan \
# --cxsast_base_url http://192.168.3.84 \
# --cxsast_username $CXSAST_USERNAME \
# --cxsast_password $CXSAST_PASSWORD \
# --preset All \
# --incremental False \
# --location_type Folder \
# --location_path /home/happy/Documents/JavaVulnerableLab \
# --project_name /CxServer/happy-2022-11-21 \
# --exclude_folders "test,integrationtest" \
# --exclude_files "*min.js" \
# --report_csv cx-report.csv \
# --full_scan_cycle 10
