from CheckmarxPythonSDK.CxOne.AccessControlAPI import (
    get_group_by_name
)
from CheckmarxPythonSDK.CxOne.KeycloakAPI import (
    create_group,
    create_subgroup,
)
from src.log import logger


def get_or_create_groups(
        group_full_name: str,
        cxone_tenant_name: str
) -> str:
    group = get_group_by_name(realm=cxone_tenant_name, group_name=group_full_name)
    if group:
        group_id = group.id
        logger.info(f"group {group_full_name} found. Its id is: {group_id}")
        return group_id
    logger.info(f"group {group_full_name} not found. It contains sub groups.")
    group_id = create_all_groups(cxone_tenant_name=cxone_tenant_name, group_full_name=group_full_name)
    logger.info(f"group {group_full_name} created, id: {group_id}")
    return group_id


def create_all_groups(cxone_tenant_name, group_full_name) -> str:
    group_names = group_full_name.split("/")
    root_group_name = group_names[0]
    root_group_id = create_root_group_if_not_exist(cxone_tenant_name, root_group_name)
    if len(group_names) == 1:
        return root_group_id
    group_id = create_sub_groups(
        cxone_tenant_name=cxone_tenant_name,
        group_names=group_names,
        root_group_id=root_group_id
    )
    return group_id


def create_sub_groups(cxone_tenant_name, group_names, root_group_id) -> str:
    parent_group_id = root_group_id
    for index, group_name in enumerate(group_names):
        if index == 0:
            continue
        group_path = "/".join(group_names[0: index + 1])
        group = get_group_by_name(realm=cxone_tenant_name, group_name=group_path)
        if not group:
            logger.info(f"current group: {group_path} does not exist, start create")
            create_subgroup(realm=cxone_tenant_name, group_id=parent_group_id, subgroup_name=group_name)
            logger.info(f"finish create group: {group_path}")
            group = get_group_by_name(realm=cxone_tenant_name, group_name=group_path)
        parent_group_id = group.id
    return parent_group_id


def create_root_group_if_not_exist(cxone_tenant_name, root_group_name) -> str:
    root_group = get_group_by_name(realm=cxone_tenant_name, group_name=root_group_name)
    if root_group:
        root_group_id = root_group.id
        logger.info(f"root group {root_group_name} exist. id: {root_group_id}")
    else:
        logger.info(f"root group not exist, start create root group")
        create_group(realm=cxone_tenant_name, group_name=root_group_name)
        root_group = get_group_by_name(realm=cxone_tenant_name, group_name=root_group_name)
        root_group_id = root_group.id
        logger.info(f"root group {root_group_name} created. id: {root_group_id}")
    return root_group_id
