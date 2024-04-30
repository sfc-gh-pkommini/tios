import streamlit as st

from .models import get_sfroles, get_sfdeployments, get_saved_filters


def init_session_state() -> None:
    """
    Initializes the various keys that will be used to save state.

    Returns: None. Only updates session_state.
    """
    if "df_tios_asset_vulns" not in st.session_state:
        st.session_state.df_tios_asset_vulns = None
    if "df_tios_asset_vulns_names_list" not in st.session_state:
        st.session_state.df_tios_asset_vulns_names_list = None
    if "table_data" not in st.session_state:
        st.session_state.table_data = None
    if "df_sfroles" not in st.session_state:
        st.session_state.df_sfroles = None
    if "df_sfdeployments" not in st.session_state:
        st.session_state.df_sfdeployments = None
    if "search_app_page_number" not in st.session_state:
        st.session_state.search_app_page_number = None
    if "search_app_filters" not in st.session_state:
        st.session_state.search_app_filters = {}
    if "filter_to_load" not in st.session_state:
        st.session_state.filter_to_load = None
    if "df_saved_filters" not in st.session_state:
        st.session_state.df_saved_filters = None
    if "form_notification_center" not in st.session_state:
        st.session_state.form_notification_center = None
    if "filter_to_delete" not in st.session_state:
        st.session_state.filter_to_delete = None


def load_data_into_state() -> None:
    """
    Fetch role and deployment data using the Snowpark API and save into session_state.

    Returns: None. Only updates session_state.
    """
    st.session_state.df_sfroles = get_sfroles()
    st.session_state.df_sfdeployments = get_sfdeployments()
