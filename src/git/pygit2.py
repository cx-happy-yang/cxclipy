# from pygit2 import Repository, GitError
# from pygit2.enums import SortMode
# from src.log import logger
# from typing import List
#
#
# def get_git_commit_history(
#         location_path: str,
#         max_level: int = 100
# ) -> List[dict]:
#     result = []
#     try:
#         repo = Repository(f'{location_path}/.git')
#         for commit in repo.walk(repo.head.target, SortMode.TIME):
#             if max_level > 0:
#                 result.append(
#                     {
#                         "commit_id": str(commit.id),
#                         "commit_time": str(commit.commit_time),
#                         "committer": str(commit.committer),
#                     }
#                 )
#             else:
#                 break
#             max_level -= 1
#     except GitError:
#         logger.info('Repository not found or repository is private')
#     return result
