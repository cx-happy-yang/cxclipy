import os
from datetime import datetime
from pathlib import Path
import tempfile
import pathlib
from zipfile import ZipFile, ZIP_DEFLATED
from src.log import logger


def get_cx_supported_file_extensions():
    return ['.ac', '.am', '.apexp', '.app', '.apxc', '.asax', '.ascx', '.asp', '.aspx', '.bas', '.c', '.c++', '.cbl',
            '.cc', '.cfg', '.cgi', '.cls', '.cmake', '.cmp', '.cob', '.component', '.conf', '.config',
            '.configurations', '.cpp', '.cpy', '.cs', '.cshtml', '.csproj', '.csv', '.ctl', '.ctp', '.cxx', '.dart',
            '.dspf', '.dsr', '.ec', '.eco', '.env', '.env_cxsca-container-build-args', '.erb', '.evt', '.frm', '.ftl',
            '.go', '.gradle', '.groovy', '.gsh', '.gsp', '.gtl', '.gvy', '.gy', '.h', '.h++', '.handlebars', '.hbs',
            '.hh', '.hpp', '.htm', '.html', '.hxx', '.inc', '.ini', '.jade', '.java', '.js', '.jsf', '.json', '.jsp',
            '.jspdsbld', '.jspf', '.jsx', '.kt', '.kts', '.latex', '.lock', '.lua', '.m', '.master', '.mf', '.mod',
            '.mustache', '.npmrc', '.object', '.page', '.pc', '.pck', '.pco', '.ph', '.php', '.php3', '.php4', '.php5',
            '.phtm', '.phtml', '.pkb', '.pkh', '.pks', '.pl', '.plist', '.pls', '.plx', '.pm', '.private', '.pro',
            '.properties', '.psgi', '.pug', '.py', '.rb', '.report', '.resolved', '.rev', '.rhtml', '.rjs', '.rpg',
            '.rpg38',
            '.rpgle', '.rs', '.rxml',  '.sbt', '.scala', '.snapshot', '.sqb', '.sql', '.sqlrpg', '.sqlrpgle', '.sum',
            '.swift', '.tag', '.target', '.testtarget', '.tex', '.tgr', '.tld', '.toml', '.tpl', '.trigger', '.ts',
            '.tsx', '.twig', '.txt', '.vb', '.vbp', '.vbproj', '.vbs', '.vm', '.vue', '.wod', '.workflow', '.xaml',
            '.xhtml', '.xib', '.xml', '.xsaccess', '.xsapp', '.xsjs', '.xsjslib', '.yaml', '.yarnrc', '.yml']


def get_cx_supported_file_without_extensions():
    return ["dockerfile", "cartfile", "podfile", "gemfile", "cpanfile", "exclude", "head", "master", "main",
            "commit_editmsg", "config", "description", "index", "packed-refs"]


def group_str_by_wildcard_character(exclusions):
    """

    Args:
        exclusions (str): comma separated string
        for example, "*.min.js,readme,*.txt,test*,*doc*"

    Returns:
        dict
        {
         "prefix_list": ["test"], # wildcard (*) at end, but not start
         "suffix_list": [".min.js", ".txt"],  # wildcard (*) at start, but not end
         "inner_List": ["doc"],   # wildcard (*) at both end and start
         "word_list": ["readme"]  # no wildcard
        }
    """
    result = {
        "prefix_list": [],
        "suffix_list": [],
        "inner_List": [],
        "word_list": [],
    }
    if not exclusions:
        return result
    string_list = exclusions.lower().split(',')
    string_set = set(string_list)
    for string in string_set:
        new_string = string.strip()
        # ignore any string that with slash or backward slash
        if '/' in new_string or "\\" in new_string:
            continue
        if new_string.endswith("*") and not new_string.startswith("*"):
            result["prefix_list"].append(new_string.rstrip("*"))
        elif new_string.startswith("*") and not new_string.endswith("*"):
            result["suffix_list"].append(new_string.lstrip("*"))
        elif new_string.endswith("*") and new_string.startswith("*"):
            result["inner_List"].append(new_string.strip("*"))
        else:
            result["word_list"].append(new_string)
    return result


def should_be_excluded(exclusions, target):
    """

    Args:
        exclusions (str):
        target (str):

    Returns:

    """
    result = False
    target = target.lower()
    groups_of_exclusions = group_str_by_wildcard_character(exclusions)
    if target.startswith(tuple(groups_of_exclusions["prefix_list"])):
        result = True
    if target.endswith(tuple(groups_of_exclusions["suffix_list"])):
        result = True
    if any([True if inner_text in target else False for inner_text in groups_of_exclusions["inner_List"]]):
        result = True
    if target in groups_of_exclusions["word_list"]:
        result = True
    return result


def add_java_file():
    temp_dir = tempfile.gettempdir()
    file_name = temp_dir + "/HelloWorld.java"
    with open(file=file_name, mode="w") as file:
        file.write(
            """class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello World!");
    }
}
            """
        )
    return file_name


def create_zip_file_from_location_path(
        location_path_str: str,
        project_id: str,
        exclude_folders_str: str = None,
        exclude_files_str: str = None,
        include_dot_git_folder: bool = None,
) -> str:
    """

    Args:
        location_path_str (str):
        project_id (str):
        exclude_folders_str (str): comma separated string
        exclude_files_str (str): comma separated string
        include_dot_git_folder (bool):

    Returns:
        str (ZIP file path)
    """
    exclude_folders = ".*,bin,target,images,Lib,node_modules"
    exclude_files = "*.min.js"
    if exclude_folders_str is not None:
        exclude_folders += ","
        exclude_folders += exclude_folders_str
    if exclude_files_str is not None:
        exclude_files += ","
        exclude_files += exclude_files_str
    temp_dir = tempfile.gettempdir()
    extensions = get_cx_supported_file_extensions()
    file_without_extensions = get_cx_supported_file_without_extensions()
    path = Path(location_path_str)
    if not path.exists():
        logger.error(f"{location_path_str} does not exist")
        return ""
    absolute_path_str = str(os.path.normpath(path.absolute()))
    file_path = f"{temp_dir}/{project_id}.zip"
    try:
        tmp_java_file = add_java_file()
        delete_zip_file(file_path)
        logger.info(f"creating zip file by zip the source code folder: {location_path_str}")
        with ZipFile(file_path, "w", ZIP_DEFLATED) as zip_file:
            root_len = len(absolute_path_str) + 1
            for base, dirs, files in os.walk(absolute_path_str):
                path_folders = base.split(os.sep)
                evaluate_dot_git_folder = True
                if include_dot_git_folder:
                    evaluate_dot_git_folder = ".git" not in path_folders
                if evaluate_dot_git_folder and any(
                        [should_be_excluded(exclude_folders, folder) for folder in path_folders]):
                    continue
                for file in files:
                    file_name = file.lower()
                    if "." not in file_name and file_name not in file_without_extensions:
                        continue
                    if "." in file_name and not file_name.endswith(tuple(extensions)):
                        continue
                    if should_be_excluded(exclude_files, file_name):
                        continue
                    fn = os.path.join(base, file)
                    zip_file.write(fn, fn[root_len:])
            zip_file.write(tmp_java_file, "HelloWorld.java")
        list_file_stats(file_path)
    except (FileExistsError, FileNotFoundError, PermissionError, OSError, IOError) as e:
        logger.error(f"Failed to create zip file: {file_path}. Error message: {e}")
    logger.info(f"ZIP file created: {file_path}")
    return file_path


def delete_zip_file(zip_file_path: str):
    logger.info(f"start deleting zip file: {zip_file_path}")
    path = Path(zip_file_path)
    if not path.exists():
        return
    pathlib.Path(zip_file_path).unlink()
    logger.info(f"Finish deleting zip file: {zip_file_path}")


def list_file_stats(zip_file_path: str):
    file_stats = os.stat(zip_file_path)
    file_size = file_stats.st_size
    last_modified = file_stats.st_mtime
    creation_time = file_stats.st_ctime
    last_modified_str = datetime.fromtimestamp(last_modified).strftime("%Y-%m-%d %H:%M:%S")
    creation_time_str = datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M:%S")
    logger.info(
        f"zip file stats: "
        f"File Size: {file_size} bytes "
        f"Last Modified: {last_modified_str} "
        f"Creation Time: {creation_time_str} "
    )


def list_zip_file_content(zip_file_path: str):
    logger.info(f"contents of the zip file {zip_file_path} will be the following:")
    with ZipFile(zip_file_path) as myzip:
        for file in myzip.infolist():
            logger.info(
                f"is_dir: {file.is_dir()},filename: {file.filename},file_size: {file.file_size},compress_size: "
                f"{file.compress_size},compress_type: {file.compress_type}"
            )

