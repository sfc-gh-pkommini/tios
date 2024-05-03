[![linting-action](https://github.com/sfc-gh-pkommini/tios/actions/workflows/ci.yaml/badge.svg)](https://github.com/sfc-gh-pkommini/tios/actions/workflows/ci.yaml)

# Vulnerability and Threat Intelligence on Snowflake - Vuln Asset Search Streamlit App

TIOS is a user interface that has the following features:

1. TIOS Dashboards
2. Search App to search of vulns that impact snowflake assets

## Setting Up a Local Python Environment

1. Install `miniconda`

   ```sh
   brew install miniconda
   conda init zsh
   ```

1. Create a python 3.10 environment compatible with snowpark

   ```sh
   conda create \
     --name streamlit-tios python=3.10 \
     --override-channels \
     -c https://repo.anaconda.com/pkgs/snowflake
   ```

1. Activate environment and install packages

   ```sh
   conda activate streamlit-tios
   pip install --upgrade -r requirements-dev.txt
   ```

1. Create `.streamlit/secrets.toml`

   ```
    [snowflake]
    user="<my_ldap_id>"
    authenticator="externalbrowser"
    account="my_account_id"
    warehouse="DEV_WH"
    database="my_db"
    schema="TIOS_DEV"
    role="my_tios_role"
   ```

With this your local environment is ready to run the application.

## Running TIOS Locally

Activate the environment and run the app

```sh
conda activate streamlit-tios
streamlit run tios/1_tios_app.py
```

## Deploying to SIS from Local

We use snowcli to do the deployments.

1. Create `~/.snowflake/config.toml` to setup connections required by snowflakecli. You'll need [account locator](https://docs.snowflake.com/en/user-guide/admin-account-identifier#finding-the-organization-and-account-name-for-an-account)

   ```conf
    [connections]

    [connections.tios_demo]
    account = "my_account_id" # Use account locator
    user = "my_username"
    authenticator = "externalbrowser"
    database = "my_db"
    schema = "TIOS_DEMO"
    warehouse = "MY_WH"
    role = "my_tios_role"
   ```

1. Install and Setup snowflakecli using instructions

   ```bash
   pip install git+https://github.com/Snowflake-Labs/snowcli.git@v2.2.0
   ```

1. Deploy the Streamlit App

   ```bash
   snow streamlit deploy -c tios_demo --project=./ --replace
   ```
