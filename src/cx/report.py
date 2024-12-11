import csv
from src.log import logger
from CheckmarxPythonSDK.CxOne import get_sast_results_by_scan_id


def generate_sast_report(
        cxone_server: str,
        project_id: str,
        scan_id: str,
        report_file_path: str
) -> str:
    """

    Args:
        cxone_server (str):
        project_id (str):
        scan_id (str):
        report_file_path (str):

    Returns:

    """
    logger.info("start report generation")
    offset = 0
    limit = 100
    page = 1
    sast_results_collection = get_sast_results_by_scan_id(scan_id=scan_id, offset=offset, limit=limit)
    total_count = int(sast_results_collection.get("totalCount"))
    sast_results = sast_results_collection.get("results")
    if total_count > limit:
        while True:
            offset = page * limit
            if offset >= total_count:
                break
            sast_results_collection = get_sast_results_by_scan_id(scan_id=scan_id, offset=offset, limit=limit)
            page += 1
            sast_results.extend(sast_results_collection.get("results"))
    report_content = []
    for result in sast_results:
        link = f"{cxone_server}/results/{scan_id}/{project_id}/sast"
        report_content.append(
            {
                "QueryID": result.query_id,
                "QueryIDStr": result.query_id_str,
                "LanguageName": result.language_name,
                "QueryGroup": result.query_group,
                "CweID": result.cwe_id,
                "ConfidenceLevel": result.confidence_level,
                "Compliances": result.compliances,
                "FirstScanID": result.first_scan_id,
                "FirstFoundAt": result.first_found_at,
                "Status": result.status,
                "Query": result.query_name,
                "SrcFileName": result.nodes[0].fileName,
                "Line": result.nodes[0].line,
                "Column": result.nodes[0].column,
                "NodeId": result.nodes[0].nodeHash,
                "Name": result.nodes[0].fullName,
                "DestFileName": result.nodes[-1].fileName,
                "DestLine": result.nodes[-1].line,
                "DestColumn": result.nodes[-1].column,
                "DestNodeId": result.nodes[-1].nodeHash,
                "DestName": result.nodes[-1].fullName,
                "Result State": result.state,
                "Result Severity": result.severity,
                "Assigned To": "",
                "Comment": "",
                "Link": link,
                "Result Status": result.status,
                "Detection Date": result.found_at,
                "SimilarityID": result.similarity_id
            }
        )
    with open(report_file_path, 'w', newline='') as csvfile:
        fieldnames = ["QueryID", "QueryIDStr", "LanguageName", "QueryGroup", "CweID", "ConfidenceLevel", "Compliances",
                      "FirstScanID", "FirstFoundAt", "Status",
                      "Query", "SrcFileName", "Line", "Column", "NodeId", "Name", "DestFileName", "DestLine",
                      "DestColumn", "DestNodeId", "DestName", "Result State", "Result Severity", "Assigned To",
                      "Comment", "Link", "Result Status", "Detection Date", "SimilarityID"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in report_content:
            writer.writerow(result)
    logger.info(f"csv report generated successfully at {report_file_path}")
    return report_file_path
