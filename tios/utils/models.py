import json
from typing import Any, Dict

import pandas as pd
import streamlit as st
from snowflake.snowpark import Window
from snowflake.snowpark.functions import (
    col,
    count,
    count_distinct,
    in_,
    lit,
    lower,
    max,
    rank,
    to_timestamp,
    to_varchar,
    when,
)

from .constants import *
from .db import init_connection
from .utils import get_offset


@st.cache_data(ttl=7200)
def get_asset_vulns(
    filters: dict,
    page_size: int = DEFAULT_PAGE_SIZE,
    page_number: int = 0,
) -> pd.DataFrame:
    session = init_connection("snowflake")
    offset = get_offset(
        page_size,
        page_number,
    )

    search_term_host = filters.get("search_term_host")
    search_term_vuln = filters.get("search_term_vuln")
    search_term_pkg = filters.get("search_term_pkg")

    published_date_start = filters.get("published_date_start")
    published_date_end = filters.get("published_date_end")
    severities = filters.get("severities")
    envs = filters.get("envs")
    sfroles = filters.get("sfroles")
    sfdeployments = filters.get("sfdeployments")

    df = session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)

    if published_date_start and published_date_end:
        df = df.filter(
            (to_timestamp(col("VULNDB_PUBLISHED_DATE")) >= published_date_start)
            & (to_timestamp(col("VULNDB_PUBLISHED_DATE")) <= published_date_end)
        )

    if severities:
        df = df.filter(
            in_([col("SEVERITY")], list(map(lambda x: x.lower(), severities)))
        )

    if envs:
        envs_list = []
        for csp in CLOUD_PROVIDERS:
            envs_list += list(map(lambda x: f"{csp}_{x.lower()}", envs))

        df = df.filter(
            in_(
                [lower(col("CONTAINER_VIRTUAL_MACHINE_PROJECTS"))],
                envs_list,
            )
        )

    if sfroles:
        df = df.filter(
            in_(
                [lower(col("SFROLE"))],
                sfroles,
            )
        )

    if sfdeployments:
        df = df.filter(
            in_(
                [lower(col("SFDEPLOYMENT"))],
                sfdeployments,
            )
        )

    if search_term_host:
        search_term_host_wildcard = f"%{search_term_host.lower()}%"
        df = df.filter(
            lower(col("CONTAINER_VIRTUAL_MACHINE_EXTERNALID")).like(
                lit(search_term_host_wildcard)
            )
        )

    if search_term_vuln:
        df = df.filter(lower(col("CVE_ID")) == lower(lit(search_term_vuln)))

    if search_term_pkg:
        search_term_pkg_wildcard = f"%{search_term_pkg.lower()}%"
        df = df.filter(
            (col("TITLE").like(lit(search_term_pkg_wildcard)))
            | (col("CPE_PURL_PKG").like(lit(search_term_pkg_wildcard)))
            | (col("HOSTED_TECHNOLOGY_NAME").like(lit(search_term_pkg_wildcard)))
        )

    df = (
        df.select(
            TIOS_VULN_ASSET_JOIN_TABLE_COLUMNS + [count("*").over().alias("FULL_COUNT")]
        )
        .order_by([col("CVSS"), col("VULNDB_PUBLISHED_DATE").desc()], ascending=[0, 0])
        .limit(
            n=page_size,
            offset=offset,
        )
    )
    return pd.DataFrame(df.collect())


@st.cache_data(ttl=7200)
def total_vulns() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_exact_match = session.table(
        TIOS_CPE_MATCH_CONSOLIDATED_TABLE
    ).select(count_distinct(col("title")).alias("vuln_count"))
    return pd.DataFrame(df_tios_asset_vulns_exact_match.collect())


@st.cache_data(ttl=7200)
def total_hosts_affected() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_exact_match = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)
        .select(
            col("container_virtual_machine_projects").alias("env"),
            col("container_virtual_machine_externalid"),
        )
        .distinct()
        .group_by(
            col("env"),
        )
        .agg(
            count_distinct(col("container_virtual_machine_externalid")).alias(
                "HOST_COUNT"
            )
        )
    )
    return pd.DataFrame(df_tios_asset_vulns_exact_match.collect())


@st.cache_data(ttl=7200)
def most_recent_vuln_pub_date() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_matches_table = session.table(
        TIOS_CPE_MATCH_CONSOLIDATED_TABLE
    ).select(
        to_varchar(max(col("vulndb_published_date")), "DY, DD MON YYYY").alias(
            "MOST RECENT PUBLISHED"
        )
    )

    return pd.DataFrame(df_tios_asset_vulns_matches_table.collect())


@st.cache_data(ttl=7200)
def most_recent_vuln_mod_date() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_matches_table = session.table(
        TIOS_CPE_MATCH_CONSOLIDATED_TABLE
    ).select(
        to_varchar(max(col("vulndb_last_modified")), "DY, DD MON YYYY").alias(
            "MOST RECENT MODIFIED"
        )
    )

    return pd.DataFrame(df_tios_asset_vulns_matches_table.collect())


@st.cache_data(ttl=7200)
def host_to_vuln_counts() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_exact_match = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)
        .select(
            col("title"),
            col("sfrole"),
            col("sfdeployment"),
            col("container_virtual_machine_projects").alias("csp"),
            col("container_virtual_machine_externalid").alias("host"),
        )
        .distinct()
        .group_by(
            col("host"),
            col("sfrole"),
            col("sfdeployment"),
            col("csp"),
        )
        .agg(count_distinct(col("title")).alias("vuln_count"))
        .order_by(col("vuln_count"), ascending=False)
        .limit(10)
    )
    return pd.DataFrame(df_tios_asset_vulns_exact_match.collect())


@st.cache_data(ttl=7200)
def vuln_to_host_counts() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_tios_asset_vulns_exact_match = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)
        .select(
            col("title"),
            col("cve_id"),
            col("cvss"),
            col("container_virtual_machine_externalid").alias("host"),
            col("container_virtual_machine_projects").alias("csp"),
        )
        .distinct()
        .group_by(
            col("title"),
            col("cve_id"),
            col("cvss"),
        )
        .agg(count_distinct(col("host")).alias("host_count"))
        .order_by(col("host_count"), ascending=False)
        .limit(10)
    )
    return pd.DataFrame(df_tios_asset_vulns_exact_match.collect())


@st.cache_data(ttl=7200)
def severity_counts() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_ranked = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)
        .select(
            col("vulndb_id"),
            col("cve_id"),
            col("cvss"),
            col("generated_on"),
            (
                when(col("cvss") >= lit(9.0), lit("CRITICAL"))
                .when((col("cvss") >= lit(7.0)) & (col("cvss") < lit(9.0)), lit("HIGH"))
                .when(
                    (col("cvss") >= lit(4.0)) & (col("cvss") < lit(7.0)), lit("MEDIUM")
                )
                .otherwise(lit("LOW"))
                .as_("severity")
            ),
            (
                rank()
                .over(
                    Window.partition_by(col("vulndb_id"), col("cve_id")).order_by(
                        col("generated_on")
                    )
                )
                .alias("rank")
            ),
        )
        .distinct()
    )
    df_tios_asset_vulns_exact_match = (
        df_ranked.select(
            col("severity"),
            col("cvss"),
        )
        .filter(col("rank") == lit(1))
        .group_by(col("severity"))
        .agg(count(col("cvss")).alias("counts"))
    )
    return pd.DataFrame(df_tios_asset_vulns_exact_match.collect())


@st.cache_data(ttl=7200)
def get_sfroles() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_sfroles = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE).select("SFROLE").distinct()
    )
    return pd.DataFrame(df_sfroles.collect())


@st.cache_data(ttl=7200)
def get_sfdeployments() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_sfdeployments = (
        session.table(TIOS_CPE_MATCH_CONSOLIDATED_TABLE)
        .select("SFDEPLOYMENT")
        .distinct()
    )
    return pd.DataFrame(df_sfdeployments.collect())


def get_saved_filters() -> pd.DataFrame:
    session = init_connection("snowflake")
    df_saved_filters = session.table(SAVED_FILTERS_TABLE).order_by(
        [col("CREATED_ON").desc()]
    )
    return pd.DataFrame(df_saved_filters.collect())


def delete_saved_filter(filter_name: str) -> int:
    session = init_connection("snowflake")
    saved_filters_table = session.table(SAVED_FILTERS_TABLE)
    deleted = saved_filters_table.delete(
        condition=((saved_filters_table.filter_name == filter_name)),
    )

    return int(deleted.rows_deleted)


def add_saved_filter(filter_name: str, filter_body: Dict) -> Any:
    session = init_connection("snowflake")
    df_saved_filters = pd.DataFrame(
        [
            [filter_name, filter_body],
        ],
        columns=["FILTER_NAME", "FILTER_PARAMS"],
    )
    df_written = session.write_pandas(df_saved_filters, SAVED_FILTERS_TABLE)
    st.session_state.df_saved_filters = get_saved_filters()
    return df_written.count()


def is_duplicate_filter_name(filter_name: str) -> bool:
    df_saved_filters = get_saved_filters()
    if df_saved_filters.empty:
        return False

    return not df_saved_filters.loc[
        df_saved_filters["FILTER_NAME"] == filter_name
    ].empty


def is_duplicate_filter_body(filter_body: Dict) -> bool:
    df_saved_filters = get_saved_filters()
    if df_saved_filters.empty:
        return False

    df_saved_filters["FILTER_PARAMS"] = df_saved_filters["FILTER_PARAMS"].map(
        lambda x: json.loads(x)
    )

    return not df_saved_filters.loc[
        df_saved_filters["FILTER_PARAMS"] == filter_body
    ].empty
