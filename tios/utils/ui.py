import json
from datetime import date, datetime, timedelta
from typing import Any, List, Tuple

import plotly.express as px
import streamlit as st

from .constants import *
from .models import (
    delete_saved_filter,
    add_saved_filter,
    get_saved_filters,
    get_asset_vulns,
    host_to_vuln_counts,
    is_duplicate_filter_body,
    is_duplicate_filter_name,
    most_recent_vuln_mod_date,
    most_recent_vuln_pub_date,
    severity_counts,
    total_hosts_affected,
    total_vulns,
    vuln_to_host_counts,
)
from .utils import contains_malicious_chars


def draw_layout_grid(
    rows: int,
    spec: List[float],
    key: str = "layout_grid",
    draw_border: bool = False,
) -> None:
    grid: List[Any] = [None] * rows

    for i in range(rows):
        # with st.container(border=draw_border):
        with st.container():
            grid[i] = st.columns(spec, gap="small")
    st.session_state[key] = grid


def draw_dashboard() -> None:
    high_level_metrics_grid_layout_key = "high_level_metrics_grid_layout"

    draw_layout_grid(3, [0.50, 0.50], key=high_level_metrics_grid_layout_key)
    high_level_metrics_grid_layout = st.session_state[
        high_level_metrics_grid_layout_key
    ]

    with high_level_metrics_grid_layout[0][0]:
        df_total_vulns = total_vulns()
        vuln_count = df_total_vulns.iloc[0]["VULN_COUNT"]
        st.metric(
            label="Total Vulnerabilities in Snowflake Assets",
            value=vuln_count,
        )

    with high_level_metrics_grid_layout[0][1]:
        df_total_hosts = total_hosts_affected()
        impacted_host_count = df_total_hosts["HOST_COUNT"].sum()
        st.metric(
            label="Total Impacted Host Count",
            value=impacted_host_count,
        )

    with high_level_metrics_grid_layout[2][0]:
        df_most_recent_vuln_pub_date = most_recent_vuln_pub_date()
        pub_date = df_most_recent_vuln_pub_date.iloc[0]["MOST RECENT PUBLISHED"]
        st.metric(label="Most Recent Published Disclosure", value=pub_date)

    with high_level_metrics_grid_layout[2][1]:
        df_most_recent_vuln_mod_date = most_recent_vuln_mod_date()
        mod_date = df_most_recent_vuln_mod_date.iloc[0]["MOST RECENT MODIFIED"]
        st.metric(label="Most Recent Modified Disclosure", value=mod_date)

    st.markdown("""---""")

    counts_grid_layout_key = "counts_grid_layout"
    draw_layout_grid(1, [0.5, 0.5], key=counts_grid_layout_key)
    counts_grid_layout = st.session_state[counts_grid_layout_key]

    with counts_grid_layout[0][0]:
        st.write("Total Hosts Affected by Environment")
        df_total_hosts_affected = total_hosts_affected()
        fig = px.bar(
            df_total_hosts_affected,
            x="HOST_COUNT",
            y="ENV",
            orientation="h",
            text_auto=True,
        )
        fig.update_traces(
            textfont_size=14,
            textangle=0,
            textposition="auto",
            cliponaxis=False,
        )
        st.write(fig)

    with counts_grid_layout[0][1]:
        st.write("Severities of Vulnerabilities Affecting Hosts")
        severity_counts_df = severity_counts()
        severity_metrics_grid_layout_key = "severity_metrics_grid_layout"
        draw_layout_grid(3, [0.5, 0.5], key=severity_metrics_grid_layout_key)
        severity_metrics_grid_layout = st.session_state[
            severity_metrics_grid_layout_key
        ]

        with severity_metrics_grid_layout[0][0]:
            critical_vuln_count = severity_counts_df.iloc[0]["COUNTS"]
            st.metric(
                label="Critical Severity",
                value=critical_vuln_count,
            )

        with severity_metrics_grid_layout[0][1]:
            high_vuln_count = severity_counts_df.iloc[1]["COUNTS"]
            st.metric(
                label="High Severity",
                value=high_vuln_count,
            )

        with severity_metrics_grid_layout[2][0]:
            med_vuln_count = severity_counts_df.iloc[2]["COUNTS"]
            st.metric(
                label="Medium Severity",
                value=med_vuln_count,
            )
        with severity_metrics_grid_layout[2][1]:
            low_vuln_count = severity_counts_df.iloc[3]["COUNTS"]
            st.metric(
                label="Low Severity",
                value=low_vuln_count,
            )

    st.markdown("""---""")

    st.write("Top 10 Vulnerable Hosts")
    df_host_to_vulns_counts = host_to_vuln_counts()
    st.dataframe(df_host_to_vulns_counts)

    st.write("Top 10 Vulnerablities Affecting Hosts")
    df_vuln_to_host_counts = vuln_to_host_counts()
    st.dataframe(df_vuln_to_host_counts)

    # df_most_recent_vuln_affecting_hosts = most_recent_vuln_affecting_hosts()
    # st.dataframe(df_most_recent_vuln_affecting_hosts)
    # df_most_recent_vuln_details = most_recent_vuln_details()
    # st.dataframe(df_most_recent_vuln_details)
    # df_top_10_cves_affecting_assets = top_10_cves_affecting_assets()
    # st.dataframe(df_top_10_cves_affecting_assets)

    # Summary of counts of critical, high, medium, low vulns at Snowflake
    # Top 10 by CVSS
    # Top Vulnerable orgs
    # Trending vulns
    # Top 10 by EPSS
    # Top 10 CVEs


def load_filter(filter_name, filter_body):
    st.session_state.filter_to_load = {
        "filter_name": filter_name,
        "filter_body": filter_body,
    }
    st.session_state.save_filter = False


def delete_filter(filter_name, filter_body):
    if (
        st.session_state.filter_to_load
        and "filter_name" in st.session_state.filter_to_load
        and st.session_state.filter_to_load["filter_name"] == filter_name
        and st.session_state.filter_to_load["filter_body"] == filter_body
    ):
        st.session_state.filter_to_load = None
    delete_saved_filter(filter_name)


def set_delete_filter_state(filter_name, filter_body):
    st.session_state.filter_to_delete = {
        "filter_name": filter_name,
        "filter_body": filter_body,
    }


def draw_expander() -> None:
    if st.session_state.filter_to_delete is not None:
        delete_filter(
            st.session_state.filter_to_delete["filter_name"],
            st.session_state.filter_to_delete["filter_body"],
        )
        st.session_state.filter_to_delete = None

    df_saved_filters = get_saved_filters()
    filters_count = len(df_saved_filters)
    search_app_expander_grid_layout_key = "search_app_expander_grid_layout_key"

    with st.expander(label="Saved Filters"):
        with st.container(
            # height=200,
            # border=False,
        ):
            draw_layout_grid(
                filters_count + 1,
                [0.15, 0.60, 0.12, 0.13],
                key=search_app_expander_grid_layout_key,
                # draw_border=False,
            )
            search_app_expander_grid_layout = st.session_state[
                search_app_expander_grid_layout_key
            ]
            with search_app_expander_grid_layout[0][0]:
                st.write("FILTER NAME")
            with search_app_expander_grid_layout[0][1]:
                st.write("FILTER PARAMS")
            with search_app_expander_grid_layout[0][2]:
                st.write("LOAD FILTER")
            with search_app_expander_grid_layout[0][3]:
                st.write("DELETE FILTER")

            for i in range(filters_count):
                filter_name = df_saved_filters.loc[i, "FILTER_NAME"]
                filter_params = json.loads(
                    str(df_saved_filters.loc[i, "FILTER_PARAMS"])
                )
                with search_app_expander_grid_layout[i + 1][0]:
                    st.code(filter_name)
                with search_app_expander_grid_layout[i + 1][1]:
                    st.code(filter_params)
                with search_app_expander_grid_layout[i + 1][2]:
                    st.button(
                        label="Load Filter",
                        key=f"{str(filter_name)}_load_submitted",
                        on_click=load_filter,
                        args=(filter_name, filter_params),
                    )
                with search_app_expander_grid_layout[i + 1][3]:
                    st.button(
                        label="Delete Filter",
                        key=f"{str(filter_name)}_delete_submitted",
                        on_click=set_delete_filter_state,
                        args=(filter_name, filter_params),
                    )


def draw_filter_form() -> Tuple:
    published_date_start_session_state = (
        datetime.strptime(
            st.session_state.filter_to_load.get("filter_body").get(
                "published_date_start"
            ),
            DATE_FORMAT,
        )
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get(
            "published_date_start"
        )
        else date.today() - timedelta(days=DEFAULT_TIME_PERIOD)
    )
    published_date_end_session_state = (
        datetime.strptime(
            st.session_state.filter_to_load.get("filter_body").get(
                "published_date_end"
            ),
            DATE_FORMAT,
        )
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("published_date_end")
        else date.today()
    )

    severities_default = (
        st.session_state.filter_to_load.get("filter_body").get("severities")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("severities")
        else ["CRITICAL", "HIGH"]
    )
    sfroles_default = (
        st.session_state.filter_to_load.get("filter_body").get("sfroles")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("sfroles")
        else []
    )
    sfdeployments_default = (
        st.session_state.filter_to_load.get("filter_body").get("sfdeployments")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("sfdeployments")
        else []
    )
    search_term_host_default = (
        st.session_state.filter_to_load.get("filter_body").get("search_term_host")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("search_term_host")
        else ""
    )
    search_term_vuln_default = (
        st.session_state.filter_to_load.get("filter_body").get("search_term_vuln")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("search_term_vuln")
        else ""
    )
    search_term_pkg_default = (
        st.session_state.filter_to_load.get("filter_body").get("search_term_pkg")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("search_term_pkg")
        else ""
    )
    filter_name_default = (
        st.session_state.filter_to_load.get("filter_name")
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_name")
        else ""
    )
    environments_default = (
        ENVIRONMENTS_LIST.index(
            st.session_state.filter_to_load.get("filter_body").get("environment")
        )
        if st.session_state.filter_to_load
        and st.session_state.filter_to_load.get("filter_body")
        and st.session_state.filter_to_load.get("filter_body").get("environment")
        else 0
    )

    with st.expander(label="Search Filters", expanded=False):
        with st.form(key="search_app_form"):
            search_app_form_grid_layout_key = "search_app_form_grid_layout"
            draw_layout_grid(6, [0.33, 0.33, 0.34], key=search_app_form_grid_layout_key)
            search_app_form_grid_layout = st.session_state[
                search_app_form_grid_layout_key
            ]

            with search_app_form_grid_layout[0][0]:
                environment = st.selectbox(
                    "Scope of Infrastructure",
                    ENVIRONMENTS_LIST,
                    index=environments_default,
                )

            with search_app_form_grid_layout[0][1]:
                published_date_start = str(
                    st.date_input(
                        "Published Date Range Start",
                        published_date_start_session_state,
                    )
                )

            with search_app_form_grid_layout[0][2]:
                published_date_end = str(
                    st.date_input(
                        "Published Date Range End",
                        published_date_end_session_state,
                    )
                )

            with search_app_form_grid_layout[1][0]:
                severities = st.multiselect(
                    "Severities",
                    options=SEVERITIES_LIST,
                    default=severities_default,
                )

            with search_app_form_grid_layout[1][1]:
                sfroles = st.multiselect(
                    "SFROLES",
                    options=st.session_state.df_sfroles,
                    default=sfroles_default,
                )

            with search_app_form_grid_layout[1][2]:
                sfdeployments = st.multiselect(
                    "SFDEPLOYMENTS",
                    options=st.session_state.df_sfdeployments,
                    default=sfdeployments_default,
                )

            with search_app_form_grid_layout[2][0]:
                search_term_host = st.text_input(
                    "Host ID",
                    key="search_term_host",
                    value=search_term_host_default,
                )

            with search_app_form_grid_layout[2][1]:
                search_term_vuln = st.text_input(
                    "CVE ID",
                    key="search_term_vuln",
                    value=search_term_vuln_default,
                )

            with search_app_form_grid_layout[2][2]:
                search_term_pkg = st.text_input(
                    "Package Name",
                    key="search_term_pkg",
                    value=search_term_pkg_default,
                )

            with search_app_form_grid_layout[3][0]:
                filter_name = st.text_input(
                    "Filter Name",
                    key="filter_name",
                    value=filter_name_default,
                )

            with search_app_form_grid_layout[4][0]:
                col1, col2 = st.columns(2, gap="medium")
                with col1:
                    filter_form_submitted = st.form_submit_button("Apply Filter")
                with col2:
                    save_filter_checkbox = st.checkbox(
                        "Save Filter",
                        key="save_filter",
                    )

    st.session_state.form_notification_center = search_app_form_grid_layout[4][1]

    if st.session_state.filter_to_load:
        st.session_state.form_notification_center.success(
            f"Loaded filter `{st.session_state.filter_to_load.get('filter_name')}`. Please Hit `Apply Filter`.",
            icon="✅",
        )

    return (
        published_date_start,
        published_date_end,
        severities,
        sfroles,
        sfdeployments,
        search_term_host.strip(),
        search_term_vuln.strip(),
        search_term_pkg.strip(),
        environment,
        filter_name,
        filter_form_submitted,
        save_filter_checkbox,
    )


def handle_page_navigation_state() -> None:
    if not st.session_state.search_app_page_number:
        st.session_state.search_app_page_number = 0

    if "prev_button" in st.session_state and st.session_state.prev_button:
        st.session_state.search_app_page_number = max(
            0, st.session_state.search_app_page_number - 1
        )
    elif "next_button" in st.session_state and st.session_state.next_button:
        st.session_state.search_app_page_number += 1


def draw_page_navigation() -> None:
    search_app_nav_grid_layout_key = "search_app_nav_grid_layout"
    draw_layout_grid(1, [0.06, 0.88, 0.06], key=search_app_nav_grid_layout_key)
    search_app_nav_grid_layout = st.session_state[search_app_nav_grid_layout_key]

    with search_app_nav_grid_layout[0][0]:
        st.button(
            key="prev_button",
            label="Prev",
            disabled=(True if st.session_state.search_app_page_number == 0 else False),
        )

    with search_app_nav_grid_layout[0][2]:
        st.button(key="next_button", label="Next")


def draw_search_app() -> None:
    (
        published_date_start,
        published_date_end,
        severities,
        sfroles,
        sfdeployments,
        search_term_host,
        search_term_vuln,
        search_term_pkg,
        environment,
        filter_name,
        filter_form_submitted,
        save_filter_checkbox,
    ) = draw_filter_form()

    # Handle form submit
    if filter_form_submitted:
        st.session_state.search_app_filters = {
            "environment": environment,
            "published_date_start": published_date_start,
            "published_date_end": published_date_end,
            "severities": severities,
            "sfroles": sfroles,
            "sfdeployments": sfdeployments,
            "search_term_host": search_term_host,
            "search_term_vuln": search_term_vuln,
            "search_term_pkg": search_term_pkg,
        }

        if (search_term_host or search_term_vuln or search_term_pkg) and (
            contains_malicious_chars(search_term_host)
            or contains_malicious_chars(search_term_vuln)
            or contains_malicious_chars(search_term_pkg)
        ):
            st.session_state.form_notification_center.warning(
                f"Search terms can only use `a-z,A-Z,0-9,-_` characters. Ignoring search terms.",
                icon="😈",
            )
            search_term_host = ""
            search_term_vuln = ""
            search_term_pkg = ""

        if save_filter_checkbox and not filter_name:
            st.session_state.form_notification_center.warning(
                f"A filter name was not specified and hence the filter was not saved.",
                icon="⚠️",
            )
        elif (
            save_filter_checkbox
            and filter_name
            and contains_malicious_chars(filter_name)
        ):
            st.session_state.form_notification_center.warning(
                f"Filter name can only use `a-z,A-Z,0-9,-_` characters.",
                icon="😈",
            )
        elif save_filter_checkbox and is_duplicate_filter_name(filter_name):
            st.session_state.form_notification_center.warning(
                f"A filter with name `{filter_name}` already exists.",
                icon="⚠️",
            )
        elif save_filter_checkbox and is_duplicate_filter_body(
            st.session_state.search_app_filters
        ):
            st.session_state.form_notification_center.warning(
                f"A filter with same parameters already exists.",
                icon="⚠️",
            )
        elif save_filter_checkbox:
            add_saved_filter(filter_name, st.session_state.search_app_filters)
            st.session_state.form_notification_center.success(
                f"Successfully saved filter `{filter_name}`.",
                icon="👍",
            )
        else:
            if not st.session_state.filter_to_load:
                st.session_state.form_notification_center.info(
                    f"Filter not saved.",
                    icon="👍",
                )

        # Reset state of filter to load after any filter has been submitted
        if st.session_state.filter_to_load:
            st.session_state.form_notification_center.success(
                f'Submitting search with filter `{st.session_state.filter_to_load.get("filter_name")}`.',
                icon="🔎",
            )
            st.session_state.filter_to_load = None

        st.session_state.search_app_page_number = 0
        df_search_results = get_asset_vulns(
            st.session_state.search_app_filters,
            page_number=st.session_state.search_app_page_number,
        )
    else:
        if not st.session_state.filter_to_load:
            st.session_state.form_notification_center.success(
                f"Search executed with default filter.",
                icon="🔎",
            )

        # Init page number for landing page
        handle_page_navigation_state()
        df_search_results = get_asset_vulns(
            st.session_state.search_app_filters,
            page_number=st.session_state.search_app_page_number,
        )
    if df_search_results.empty:
        results_count_msg = f"`0` results found."
    else:
        full_count = df_search_results.iloc[0]["FULL_COUNT"]
        results_count_msg = f"`{full_count}` results found. Showing page `{st.session_state.search_app_page_number + 1}` of `{full_count // DEFAULT_PAGE_SIZE + 1}`"

    # Draw saved filters expandable
    draw_expander()

    # Show results count
    st.write(results_count_msg)

    # Draw the grid of results
    st.dataframe(df_search_results)

    draw_page_navigation()


def draw_tabs() -> None:
    dashboard, search_app = st.tabs(["Dashboard", "Vulnerable Asset Search"])

    with dashboard:
        draw_dashboard()

    with search_app:
        draw_search_app()
