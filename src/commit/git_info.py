from git import Repo
from datetime import datetime, timedelta, timezone  # 新增导入timezone
from typing import List


def get_git_commit_info(repo_path: str) -> List[dict]:
    """
    Retrieve the date, email, username and hash of commits in the last 90 days

    Parameters:
        repo_path: Local path to the Git repository (e.g., ./my_repo)

    Returns:
        A list where each element is a dictionary:
        {'commit_hash': 完整哈希值, 'commit_date': ISO格式提交时间, 
         'email': 提交者邮箱, 'username': 作者名称}
    """
    try:
        # 打开Git仓库
        repo = Repo(repo_path)

        # 检查仓库有效性
        if repo.bare:
            raise Exception(f"Repository {repo_path} is a bare repo and cannot be operated on")
        
        # 关键修复：生成UTC时区的90天前时间（offset-aware）
        # datetime.now(timezone.utc) 获取当前UTC时间（带时区），再减90天
        ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
        commit_info_list = []

        # 遍历所有commit（默认按时间倒序，最新的先遍历）
        for commit in repo.iter_commits():
            # 获取commit的提交时间（Git默认返回UTC时区的offset-aware对象）
            commit_datetime = commit.committed_datetime

            # 过滤：只保留90天内的commit（此时两者都是UTC的offset-aware对象，可安全比较）
            if commit_datetime >= ninety_days_ago:
                commit_info = {
                    "commit_hash": commit.hexsha,  # 完整哈希，如需短哈希可改为 commit.hexsha[:7]
                    "commit_date": commit_datetime.isoformat(),
                    "email": commit.committer.email,
                    "username": commit.author.name
                }
                commit_info_list.append(commit_info)
            else:
                # 由于commit是倒序遍历，一旦超出90天可直接终止循环（优化性能）
                break

        return commit_info_list

    except Exception as e:
        print(f"Failed to retrieve commit information: {e}")
        return []