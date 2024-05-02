# Miscallenous constants
DEFAULT_TIME_PERIOD = 90
SNOWFLAKE_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"

# Tables
TIOS_CPE_MATCH_CONSOLIDATED_TABLE = "CPE_CONSOLIDATED_VIEW"
SAVED_FILTERS_TABLE = "TIOS_SAVED_FILTERS"

# Columns
TIOS_VULN_ASSET_JOIN_TABLE_COLUMNS = [
    "CVE_ID",
    "CVSS",
    "VENDOR",
    "PRODUCT",
    "VERSION",
    "CONTAINER_VIRTUAL_MACHINE_EXTERNALID",
    "SFROLE",
    "SFDEPLOYMENT",
    "VULNDB_LAST_MODIFIED",
    "VULNDB_PUBLISHED_DATE",
    "CPE_PURL_PKG",
    "TITLE",
    "HOSTED_TECHNOLOGY_NAME",
    "CONTAINER_VIRTUAL_MACHINE_PROJECTS",
    "EPSS_SCORE",
    "EPSS_PLUS_SCORE",
]
DEFAULT_PAGE_SIZE = 25

SEVERITY_SCORE_MAPPING = {
    "critical": [9.0, 10.0],
    "high": [7.0, 8.9],
    "medium": [4.0, 6.9],
    "low": [0.1, 3.9],
}


SEVERITIES_LIST = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]
ENVIRONMENTS_LIST = [
    "PROD",
    "CORP CLOUD",
    "CORP ENDPOINT",
    "ALL",
]
CLOUD_PROVIDERS = [
    "aws",
    "gcp",
    "azure",
]
