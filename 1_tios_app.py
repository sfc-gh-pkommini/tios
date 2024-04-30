import platform
import sys

import streamlit as st


st.set_page_config(
    page_title="TIOS App",
    layout="wide",
    initial_sidebar_state="auto",
    menu_items=None,
)


def running_on_sis():
    mac_ver = platform.mac_ver()
    if len(mac_ver) == 0:
        return True
    return len(mac_ver[0]) == 0


if running_on_sis():
    SIS = True
    sys.path.append("tios.zip")
else:
    SIS = True

from tios.utils.state import init_session_state, load_data_into_state
from tios.utils.ui import draw_tabs


# Create necessary keys in session_state
init_session_state()

load_data_into_state()

# Draw Tabs
draw_tabs()
