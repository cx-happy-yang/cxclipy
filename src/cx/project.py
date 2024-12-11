from src.log import logger
from typing import List
from CheckmarxPythonSDK.CxOne import (
    get_a_list_of_projects,
    create_a_project,
    update_a_project,
    define_parameters_in_the_input_list_for_a_specific_project,
)
from CheckmarxPythonSDK.CxOne.dto import (
    ProjectInput,
    ScanParameter,
)


def process_project(
        project_name: str,
        group_ids: List[str],
        sca_last_sast_scan_time: int
) -> str:
    project_collection = get_a_list_of_projects(name=project_name)
    if not project_collection.projects:
        logger.info("project does not exist. create project")
        project = create_a_project(
            project_input=ProjectInput(
                name=project_name,
                groups=group_ids
            )
        )
        project_id = project.id
        logger.info(f"new project name {project_name} with project_id: {project_id} created.")
    else:
        project = list(filter(lambda r: r.name == project_name, project_collection.projects))[0]
        project_id = project.id
        if not project.groups:
            project_input = ProjectInput(
                name=project.name,
                groups=group_ids,
                repo_url=project.repoUrl,
                main_branch=project.mainBranch,
                origin=project.origin,
                tags=project.tags,
                criticality=project.criticality
            )
            update_a_project(project_id, project_input)

    logger.info(f"project id: {project_id}")
    logger.info("start update project configuration")
    scan_parameters = [
        ScanParameter(
            key="scan.config.sca.ExploitablePath",
            name="exploitablePath",
            category="sca",
            origin_level="Project",
            value="false",
            value_type="Bool",
            value_type_params=None,
            allow_override=True
        ),
        ScanParameter(
            key="scan.config.sca.LastSastScanTime",
            name="lastSastScanTime",
            category="sca",
            origin_level="Project",
            value=f"{sca_last_sast_scan_time}",
            value_type="Number",
            value_type_params=None,
            allow_override=True
        ),
    ]
    define_parameters_in_the_input_list_for_a_specific_project(
        project_id=project_id,
        scan_parameters=scan_parameters
    )
    logger.info("finish update project configuration")
    return project_id
