from CheckmarxPythonSDK.CxOne.AccessControlAPI import (
    get_group_by_name
)
from CheckmarxPythonSDK.CxOne.KeycloakAPI import (
    create_group,
    create_subgroup,
)
from src.log import logger
from typing import List


def get_or_create_groups(
        group_full_name: str,
        cxone_tenant_name: str
) -> List[str]:
    group_names = [item for item in group_full_name.split("/")]
    group = get_group_by_name(realm=cxone_tenant_name, group_name=group_full_name)
    if not group:
        for index, gr in enumerate(group_names):
            if index == 0:
                group = get_group_by_name(realm=cxone_tenant_name, group_name=gr)
                if not group:
                    logger.info(f"root group {gr} not exist.")
                    logger.info(f"start creating root group: {gr}")
                    create_group(realm=cxone_tenant_name, group_name=gr)
                    logger.info(f"finish creating root group: {gr}")
            else:
                parent_group_path = "/".join(group_names[0: index])
                logger.info(f"parent group path: {parent_group_path}")
                group_path = "/".join(group_names[0: index + 1])
                logger.info(f"current group path: {group_path}")
                group = get_group_by_name(realm=cxone_tenant_name, group_name=group_path)
                if not group:
                    logger.info(f"current group {group_path} not exist.")
                    logger.info(f"start creating sub group: {group_path}, parent group name: {parent_group_path}")
                    parent_group = get_group_by_name(realm=cxone_tenant_name, group_name=parent_group_path)
                    create_subgroup(realm=cxone_tenant_name, group_id=parent_group.id, subgroup_name=gr)
                    logger.info(f"finish creating sub group: {group_path}, parent group name: {parent_group_path}")
    group = get_group_by_name(realm=cxone_tenant_name, group_name=group_full_name)
    group_id = group.id
    group_ids = [group_id]
    logger.info(f"group_ids: {group_ids}")
    return group_ids
