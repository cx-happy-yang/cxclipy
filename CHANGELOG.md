# Changelog

All notable changes to CxCliPy will be documented in this file.

## [Unreleased]

### Added
- Add `publish-CxCliPy.yml` workflow for building CxCliPy binary
- Add support for branched projects in scan function

### Changed
- Rename `python-publish.yml` to `publish-CxOneCli.yml`
- Update CheckmarxPythonSDK to 1.7.9

## [0.6.9] - 2025-01-16

### Changed
- Multiple GitHub Actions workflow updates
- Update `.gitignore`

## [0.6.8] - 2024-12-25

### Removed
- Remove filter logic

## [0.6.7] - 2024-12-24

### Added
- Add `state=['TO_VERIFY']` and `include_nodes=False` parameters

## [0.6.6] - 2024-12-23

### Added
- Add `--contributors_ignore_list` command line option

## [0.6.5] - 2024-12-20

### Fixed
- Fix can't compare offset-naive and offset-aware datetimes

## [0.6.4] - 2024-12-18

### Fixed
- Fix timezone issue

## [0.6.3] - 2024-12-16

### Added
- Add logging for contributors.csv

## [0.6.2] - 2024-12-13

### Changed
- Limit CSV file to 1MB

## [0.6.1] - 2024-12-10

### Changed
- Filter contributors to last 90 days

## [0.6.0] - 2024-12-05

### Added
- Bundle certifi cacert.pem into binary
- GitHub Actions workflow improvements

## [0.5.9] - 2024-10-24

### Changed
- Refactor Python version to 3.8

## [0.5.8] - 2024-10-20

### Added
- Add support for `contributors.csv`

### Changed
- Update CheckmarxPythonSDK to 1.4.4

## [0.5.7] - 2024-10-15

### Fixed
- Fix `scan.createdAt` convert to datetime

## [0.5.6] - 2024-10-12

### Fixed
- Fix no source code error: create HelloWorld.java in tmp folder and handle exceptions
- Fix GitHub release process

### Changed
- Use Python 3.8
- Use Ubuntu 20.04 Docker container for builds
- Install GitHub CLI in Docker container

## [0.5.5] - 2024-10-01

### Changed
- Use Ubuntu 20.04 Docker container to run jobs
- Remove commit ID check

## [0.5.3] - 2024-09-20

### Changed
- Update CheckmarxPythonSDK to 1.2.7

## [0.5.2] - 2024-09-15

### Changed
- Update requirements.txt

## [0.5.1] - 2024-09-12

### Changed
- On `*-sca` branches, ignore checking commit ID

## [0.5.0] - 2024-09-08

### Changed
- Update CheckmarxPythonSDK to 1.2.0

## [0.4.9] - 2024-09-01

### Added
- Cancel scan if commit ID is duplicated

## [0.4.8] - 2024-08-28

### Added
- Log scanners from args

## [0.4.7] - 2024-08-25

### Added
- Include git-related files (but not entire `.git` folder) in zip
- Add `get_cx_supported_file_extensions` and `get_cx_supported_file_without_extensions`

## [0.4.6] - 2024-08-20

### Fixed
- Add `Queued` status checking for `parallel_scan_cancel`
- Fix `get_a_list_of_scans` sort by `created_at` in descending order

## [0.4.5] - 2024-08-15

### Fixed
- Fix `scan_config.to_dict`

## [0.4.4] - 2024-08-10

### Changed
- Update CheckmarxPythonSDK to 1.1.6

## [0.4.3] - 2024-08-05

### Changed
- Change `--include_dot_git_folder` default to `true`

## [0.4.2] - 2024-08-01

### Added
- Add `--include_dot_git_folder` command line option

## [0.4.1] - 2024-07-28

### Added
- When scan fails, list all contents of the zip file for debugging

## [0.4.0] - 2024-07-25

### Fixed
- When `sca_exploitable_path` is false, no need to add SAST scanner

## [0.3.9] - 2024-07-20

### Changed
- GitHub Actions workflow updates

## [0.3.8] - 2024-07-15

### Added
- Add `run.sh` shell script

## [0.3.7] - 2024-07-10

### Added
- Add UPX support for binary compression
- Move `delete_zip_file` to end of process

## [0.3.6] - 2024-07-05

### Changed
- Revert `scan_commit_number` changes

## [0.3.5] - 2024-07-01

### Changed
- Refactor: `check_sast_scan_type`, `should_create_new_scan`, `create_zip_file_from_location_path`, `get_or_create_groups`, `upload_url`
- `scan_commit_number` defaults to 0

### Fixed
- Fix incremental scan issue

## [0.3.3] - 2024-06-15

### Removed
- Remove SHA-256 hash for zip file

### Fixed
- Fix statistics `None` issue
- Fix find project by exact name

## [0.3.0] - 2024-06-01

### Added
- Support for SCA exploitable path
- Support for `--scan_commit_number`
- Support for `--parallel_scan_cancel`
- Support for comma-separated `scan_tag_key` values
- Add `scan_tag_key` and `scan_tag_value` options
- Add critical statistics for SAST results
- Add committer information
- Add Java file support

### Fixed
- Fix branch always `master` issue
- Fix CSV report results link
- Fix UTC time handling
- Fix `ConnectionError` handling
- Fix full scan could be `None`

## [0.2.0] - 2024-05-01

### Added
- Initial project setup
- Basic scan functionality
- GitHub Actions CI/CD workflow
- Project configuration support
- Report generation with links

### Changed
- Rename `CxCliPy.py` to `CxOneCli.py`
