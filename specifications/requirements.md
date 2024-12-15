# requirements

## target
This is a pipeline script to run checkmarx one scans, and generate sast scan csv report.

It should make most of the fast scan features, control parallel scans, avoid duplicate scans.

The requirements are as follows:

1. incremental scan
2. apply exclusions to remove files not need to scan
3. generate csv report for sast scan
4. enforce full scan
5. create groups when required
6. create project when required
7. control parallel scan
8. control scan by number of commits
9. control sca scan with exploitable path enabled

## scan flow

1. read and parse command line options to collect the configuration
2. create groups if they were not exist
3. create project or get existing project, and update the project configuration
4. create zip file, apply exclusions
5. upload zip file
6. delete zip file
7. read last 100 git commit history
8. get last few scans of current branch
9. check if the new scan should be created
10. check sast scan type should be a full scan or not based on number of scans exist
11. for a sca scan, check if a sast scan should be included to reuse the last n days Exploitable Path results
12. create scan, wait for finish
13. display scan statistics 
14. generate sast csv report if there is sast scanner defined.

## details on requirements

### incremental scan
To apply incremental scan as much as possible to make scans finish fast.

### apply exclusions to remove files not need to scan
Based on the exclude_folders and exclude_files from command line options, skip these folders and files when creating a 
zip file.

### generate csv report for sast scan
Get the sast scan result, and create csv report

### enforce full sast scan
It is required to enforce a full sast scan for every few sast scans, because of the limitation of sast incremental scan.

### create groups when required
Create cx one groups if these groups not exist

### create project when required
Create project if it does not exist, update project configuration (rules), disable sca exploitable path on project level.

### control parallel scan
It is possible to trigger multiple scans the same time from the same project, same branch. It is required to control 
parallel scan to avoid too many scans created.

### control scan by number of commits
It can be configured to create scan based on number of commits. It can possibly reduce number of scans.

### control sca scan with exploitable path enabled
Because of the exploitable path performance issue, it is suggested to use a dedicate branch to trigger sca scan, and only
enable exploitable path for the sca scan for this branch. So it won't impact other sast scans from other branch. It is 
required to disable the exploitable path on project level.
