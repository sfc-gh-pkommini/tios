import pandas as pd
from pytest_mock import MockerFixture
from streamlit.testing.v1 import AppTest


def test_tios_app_no_interaction(
    mocker: MockerFixture,
    mock_df_roles: pd.DataFrame,
    mock_df_deployments: pd.DataFrame,
    mock_total_vulns: pd.DataFrame,
    mock_total_hosts_affected: pd.DataFrame,
    mock_most_recent_vuln_pub_date: pd.DataFrame,
    mock_most_recent_vuln_mod_date: pd.DataFrame,
    mock_severity_counts: pd.DataFrame,
    mock_host_to_vuln_counts: pd.DataFrame,
    mock_vuln_to_host_counts: pd.DataFrame,
    mock_get_asset_vulns: pd.DataFrame,
    mock_get_saved_filters: pd.DataFrame,
):
    mocker.patch("tios.utils.models.get_sfroles").return_value = mock_df_roles
    mocker.patch("tios.utils.models.get_sfdeployments").return_value = (
        mock_df_deployments
    )
    mocker.patch("tios.utils.models.total_vulns").return_value = mock_total_vulns
    mocker.patch("tios.utils.models.total_hosts_affected").return_value = (
        mock_total_hosts_affected
    )
    mocker.patch("tios.utils.models.most_recent_vuln_pub_date").return_value = (
        mock_most_recent_vuln_pub_date
    )
    mocker.patch("tios.utils.models.most_recent_vuln_mod_date").return_value = (
        mock_most_recent_vuln_mod_date
    )
    mocker.patch("tios.utils.models.severity_counts").return_value = (
        mock_severity_counts
    )
    mocker.patch("tios.utils.models.host_to_vuln_counts").return_value = (
        mock_host_to_vuln_counts
    )
    mocker.patch("tios.utils.models.vuln_to_host_counts").return_value = (
        mock_vuln_to_host_counts
    )
    mocker.patch("tios.utils.models.get_asset_vulns").return_value = (
        mock_get_asset_vulns
    )
    mocker.patch("tios.utils.models.get_saved_filters").return_value = (
        mock_get_saved_filters
    )
    at = AppTest.from_file("1_tios_app.py", default_timeout=120).run()
    assert not at.exception
