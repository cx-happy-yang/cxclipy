from git import Repo
from datetime import datetime
from typing import List


def get_git_commit_info(repo_path) -> List[dict]:
    """
    Retrieve the date and email of all commits in a Git repository

    Parameters:
        repo_path: Local path to the Git repository (e.g., ./my_repo)

    Returns:
        A list where each element is a dictionary:
        {'commit_hash': hash value, 'commit_date': commit date, 'email': committer email}
    """
    try:
        # Open the Git repository
        repo = Repo(repo_path)

        # Check if the repository is valid
        if repo.bare:
            raise Exception(f"Repository {repo_path} is a bare repo and cannot be operated on")

        commit_info_list = []
        # Iterate through all commits (in reverse chronological order, latest first)
        for commit in repo.iter_commits():
            # Commit hash (short hash)
            commit_hash = commit.hexsha
            # Commit date (committer date, i.e., the time when the commit was finally pushed to the repository)
            # Note: commit.author.date is the time when the author wrote the code, which may differ from the commit time
            commit_date = commit.committed_datetime.isoformat()
            # Committer's email
            # If you need the author's email, use commit.author.email
            email = commit.committer.email
            username = commit.author.name
            commit_info_list.append({
                "commit_date": commit_date,
                "commit_hash": commit_hash,
                "email": email,
                "username": username,
            })
        return commit_info_list

    except Exception as e:
        print(f"Failed to retrieve commit information: {e}")
        return []
