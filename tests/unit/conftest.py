import json

import pandas as pd
import pytest


@pytest.fixture
def mock_df_roles():
    return pd.DataFrame(
        [
            "foundationdb",
            "bastion",
            "sonarqube",
            "analytics_management",
            "snowhouse_loader",
            "testReproducer",
            "gluster",
            "snowservices",
            "dns_and_ntp",
            "backup",
        ],
        columns=["SFROLE"],
    )


@pytest.fixture
def mock_df_deployments():
    return pd.DataFrame(
        [
            "azeastus2_rtfdb_8",
            "azswitzerlandnorth",
            "foundationdb",
            "nginx_awsuswest2preprod8",
            "azwestus2",
            "temptest002011fdb1",
            "temptest002042fdb1",
            "azwesteuropefdb2",
            "azcanadacentralfdb2",
            "temptest001048_904_yiwu_mgmt",
        ],
        columns=["SFROLE"],
    )


@pytest.fixture
def mock_total_vulns():
    return pd.DataFrame([[9939]], columns=["VULN_COUNT"])


@pytest.fixture
def mock_total_hosts_affected():
    return pd.DataFrame(
        [
            ["AWS_Dev", 1370],
            ["Azure_dev", 240],
            [None, 4215],
            ["CorpSec-Sandbox, CorporateSecurity", 50],
            ["Azure_Prod", 2016],
            ["GCP_dev", 6],
            ["AWS_Prod", 869],
        ],
        columns=["ENV", "HOST_COUNT"],
    )


@pytest.fixture
def mock_most_recent_vuln_pub_date():
    return pd.DataFrame(
        [["Mon, 29 Jan 2024"]],
        columns=["MOST RECENT PUBLISHED"],
    )


@pytest.fixture
def mock_most_recent_vuln_mod_date():
    return pd.DataFrame(
        [["Mon, 29 Jan 2024"]],
        columns=["MOST RECENT MODIFIED"],
    )


@pytest.fixture
def mock_severity_counts():
    return pd.DataFrame(
        [
            ["MEDIUM", 6633],
            ["CRITICAL", 1891],
            ["LOW", 1001],
            ["HIGH", 7869],
        ],
        columns=["SEVERITY", "COUNTS"],
    )


@pytest.fixture
def mock_host_to_vuln_counts():
    return pd.DataFrame(
        [
            [
                "/subscriptions/f4b00c5f-f6bf-41d6-806b-e1cac4f",
                None,
                None,
                "Azure_dev",
                7158,
            ],
            [
                "i-029c11ac4d47e819b",
                None,
                None,
                "CorpSec-Sandbox, CorporateSecurity",
                7158,
            ],
            [
                "i-07f48cd795b6c22eb",
                None,
                None,
                "AWS_Dev",
                7158,
            ],
            [
                "i-07de63086f44689a4",
                None,
                None,
                "AWS_Dev",
                7158,
            ],
            [
                "i-08ac7714123ea4308",
                None,
                None,
                "AWS_Dev",
                7158,
            ],
            [
                "i-044b7ca2c3ae8acdc",
                None,
                None,
                "AWS_Dev",
                7158,
            ],
            [
                "/subscriptions/f4b00c5f-f6bf-41d6-806b-e1cac4f",
                None,
                None,
                "Azure_dev",
                7158,
            ],
            [
                "i-0234e07e699a49e32",
                None,
                None,
                "AWS_Dev",
                7158,
            ],
            [
                "i-0614834f68e4a7030",
                None,
                None,
                "CorpSec-Sandbox, CorporateSecurity",
                4643,
            ],
            [
                "i-0961782315097550b",
                None,
                None,
                "CorpSec-Sandbox, CorporateSecurity",
                4639,
            ],
        ],
        columns=["HOST", "SFROLE", "SFDEPLOYMENT", "CSP", "VULN_COUNT"],
    )


@pytest.fixture
def mock_vuln_to_host_counts():
    return pd.DataFrame(
        [
            ["OpenSSL crypto/objects/obj_dat.c OBJ_obj2txt()...", None, 7.5, 8671],
            [
                "OpenSSL crypto/x509/x509_vfy.c check_policy() ...",
                "CVE-2023-0465",
                5.3,
                8671,
            ],
            [
                "OpenSSL crypto/x509/x509_vfy.c check_policy() ...",
                "CVE-2023-0465",
                5.3,
                8671,
            ],
            [
                "OpenSSL crypto/objects/obj_dat.c OBJ_obj2txt()...",
                "CVE-2023-2650",
                6.5,
                8671,
            ],
            ["OpenSSL crypto/x509/x509_vfy.c check_policy() ...", None, 5.9, 8671],
            [
                "OpenSSL doc/man3/X509_VERIFY_PARAM_set_flags.p...",
                "CVE-2023-0466",
                5.3,
                8671,
            ],
            ["OpenSSL doc/man3/X509_VERIFY_PARAM_set_flags.p...", None, 5.3, 8671],
            ["OpenSSL crypto/dh/dh_check.c DH_check() Functi...", None, 5.3, 8611],
            [
                "OpenSSL crypto/dh/dh_check.c DH_check() Functi...",
                "CVE-2023-3446",
                5.3,
                8611,
            ],
            ["OpenSSL crypto/dh/dh_check.c DH_check() Functi...", None, 5.3, 8608],
            [
                "OpenSSL crypto/dh/dh_check.c DH_check() Functi...",
                "CVE-2023-3817",
                5.3,
                8608,
            ],
        ],
        columns=["TITLE", "CVE_ID", "CVSS", "HOST_COUNT"],
    )


@pytest.fixture
def mock_get_asset_vulns():
    return pd.DataFrame(
        [
            [
                None,
                9.9,
                "canonical",
                "ubuntu_linux",
                "22.04",
                "i-088361a030aeae3f8",
                None,
                None,
                "2023-12-13 14:36:52",
                "2022-01-31 18:46:50",
                "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*...",
                "Samba lib/adouble.c vfs_fruit Module Extended",
                "Linux Ubuntu (Streamlit-Potpourri)",
                "CorpSec-Sandbox, CorporateSecurity",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/15d2b85e-e57c-4712-9344-479fdb0b2d14/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-1",
                "bastion",
                "azsoutheastasia",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-2",
                "bastion",
                "azcanadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (cacentdnslogger-1)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/ae0c1e4e-d49e-4115-b3ba-888d77ea97a3/resourcegroups/azeastus2-teleport-rg/providers/microsoft.compute/virtualmachines/tproxy-1",
                "tproxy",
                "azeastus2",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-0",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/c4163da0-f07a-42ab-a254-9ca2bf882e98/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-2",
                "bastion",
                "azwesteurope",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-2",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/cacent-teleport-rg/providers/microsoft.compute/virtualmachines/cacent-tproxy-0",
                "tproxy",
                "canadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (metrics-receiver11",
                "AWS_Dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/4575fb04-6859-4781-8948-7f3a92dc06a3/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-1",
                "bastion",
                "azwestus2",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-2",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-1",
                "bastion",
                "azcanadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-0",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/cacent-teleport-rg/providers/microsoft.compute/virtualmachines/cacent-tauth-0",
                "tauth",
                "canadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (test-metrics-receiver2",
                "AWS_Dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16",
                "i-0cf16422e5e2cacad",
                "metrics_receiver",
                "dev",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (cacentdnslogger-2)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16",
                "i-044b7ca2c3ae8acdc",
                None,
                None,
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/4575fb04-6859-4781-8948-7f3a92dc06a3/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-0",
                "bastion",
                "azwestus2",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-1)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/15d2b85e-e57c-4712-9344-479fdb0b2d14/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-2",
                "bastion",
                "azsoutheastasia",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (metrics-receiver10)",
                "AWS_Dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/cacentdnslogger-2",
                "dnslogger",
                "azcanadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-1)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/4575fb04-6859-4781-8948-7f3a92dc06a3/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-2",
                "bastion",
                "azwestus2",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (cacent-tproxy-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/9d0cdbea-271a-458f-9c1c-06f8ce5632e1/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-0",
                "bastion",
                "azswitzerlandnorth",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16",
                "i-0decfae920bf45c2b",
                "test_metrics_receiver",
                "dev",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*  Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-1)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/c4163da0-f07a-42ab-a254-9ca2bf882e98/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-1",
                "bastion",
                "azwesteurope",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-2)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "canonical",
                "ubuntu_linux",
                "18.04"
                "/subscriptions/c4163da0-f07a-42ab-a254-9ca2bf882e98/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-0",
                "bastion",
                "azwesteurope",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:*...",
                "Samba Active Directory Domain Controller Kerbe...",
                "Linux Ubuntu (s3cleanup-destroyer)",
                "AWS_Dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/bastion-c7-0",
                "bastion",
                "azcanadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (cacentdnslogger-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "canonical",
                "ubuntu_linux",
                "18.04"
                "/subscriptions/f4b00c5f-f6bf-41d6-806b-e1cac4f1f36f/resourcegroups/azure-dev/providers/microsoft.compute/virtualmachines/v5-ubuntu",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:*...",
                "Samba Active Directory Domain Controller Kerbe...",
                "Linux Ubuntu (test-vm-3)",
                "Azure_dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16",
                "i-06f1e2a3142ab1c5e",
                "test_metrics_receiver",
                "dev",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*  Samba Active Directory Domain Controller Kerbe...",
                "Samba (test-metrics-receiver3)",
                "AWS_Dev",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16"
                "/subscriptions/314c84b6-7d62-4b85-ab37-aa65c443f82d/resourcegroups/core-servers-rg/providers/microsoft.compute/virtualmachines/cacentdnslogger-0",
                "dnslogger",
                "azcanadacentral",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (cacent-tauth-0)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "samba",
                "samba",
                "4.10.16",
                "i-02b865d69f7211167",
                "test_metrics_receiver",
                "dev",
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:a:samba:samba:4.10.16:*:*:*:*:*:*:*",
                "Samba Active Directory Domain Controller Kerbe...",
                "Samba (bastion-c7-1)",
                "Azure_Prod",
                2586454,
            ],
            [
                None,
                9.9,
                "canonical",
                "ubuntu_linux",
                "18.04",
                "i-08ac7714123ea4308",
                None,
                None,
                "2023-09-17 19:17:41",
                "2021-11-10 12:52:38",
                "cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:*...",
                "Samba Active Directory Domain Controller Kerbe...",
                "Linux Ubuntu (v5-ubuntu)",
                "Azure_dev",
                2586454,
            ],
        ],
        columns=[
            "CVE_ID",
            "CVSS",
            "VENDOR",
            "PRODUCT",
            "VERSION",
            "CONTAINER_VIRTUAL_MACHINE_EXTERNALID",
            "SFROLE",
            "SFDEPLOYMENT",
            "THREAT_INTEL_PUBLISHED_DATE",
            "THREAT_INTEL_LAST_MODIFIED",
            "CPE_PURL_PKG",
            "TITLE",
            "HOSTED_TECHNOLOGY_NAME",
            "CONTAINER_VIRTUAL_MACHINE_PROJECTS",
            "FULL_COUNT",
        ],
    )


@pytest.fixture
def mock_get_saved_filters():
    return pd.DataFrame(
        [
            [
                "test-filter-1",
                json.dumps(
                    {
                        "environment": "PROD",
                        "envs": [],
                        "published_date_end": "2024-02-09",
                        "published_date_start": "2020-11-01",
                        "search_term_host": "",
                        "search_term_pkg": "",
                        "search_term_vuln": "CVE-2024-21626",
                        "severities": ["CRITICAL"],
                        "sfdeployments": [
                            "nginx_temptest003041",
                            "nginx_temptest003008",
                            "azaustraliaeast",
                            "sonarqube",
                            "awsuswest2preprodvps2fdb1",
                            "nginx_dev",
                            "nginx_awsuseast2",
                            "azeastus2_rtfdb_8",
                        ],
                        "sfroles": [
                            "yum_repo",
                            "tenableNM",
                            "ntp",
                            "tenableSC-nginx",
                            "metrics_receiver",
                        ],
                    },
                    indent=4,
                ),
                "2024-02-07 21:03:20.191",
                "2024-02-07 21:03:20.191",
            ],
            [
                "test-filter-2",
                json.dumps(
                    {
                        "envs": ["PROD"],
                        "published_date_end": "2024-02-07",
                        "published_date_start": "2023-01-07",
                        "search_term_host": "",
                        "search_term_pkg": "",
                        "search_term_vuln": "",
                        "severities": ["HIGH"],
                        "sfdeployments": [],
                        "sfroles": [],
                    },
                    indent=4,
                ),
                "2024-02-07 21:03:20.191",
                "2024-02-07 21:03:20.191",
            ],
        ],
        columns=[
            "FILTER_NAME",
            "FILTER_PARAMS",
            "CREATED_ON",
            "MODIFIED_ON",
        ],
    )
