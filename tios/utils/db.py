import platform

import streamlit as st
from snowflake.snowpark import Session
from snowflake.snowpark.context import get_active_session


@st.cache_resource
def init_connection(account):
    def running_on_sis():
        mac_ver = platform.mac_ver()
        if len(mac_ver) == 0:
            return True
        return len(mac_ver[0]) == 0

    if not running_on_sis():
        return Session.builder.configs(st.secrets[account]).create()

    return get_active_session()
