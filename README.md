# TIOS on Streamlit

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
conda activate snowpark
streamlit run tios/1_tios_app.py
```

## Deploying to SIS from Local

We use snowcli to do the deployments.

1. Create `~/.snowflake/config.toml` to setup connections required by snowflakecli

   ```toml
    [connections]

    [connections.tios_dev]
    account = "my_account_id"
    user = "my_username"
    authenticator = "externalbrowser"
    database = "my_db"
    schema = "TIOS_DEV"
    warehouse = "DEV_WH"
    role = "my_tios_role"

    [connections.tios_uat]
    account = "my_account_id"
    user = "my_username"
    authenticator = "externalbrowser"
    database = "my_db"
    schema = "TIOS_UAT"
    warehouse = "UAT_WH"
    role = "my_tios_role"

    [connections.tios]
    account = "my_account_id"
    user = "my_username"
    authenticator = "externalbrowser"
    database = "my_db"
    schema = "TIOS"
    warehouse = "MY_WH"
    role = "my_tios_role"
   ```

1. Install and Setup snowflakecli using instructions [here](https://docs.snowflake.com/LIMITEDACCESS/snowcli/installation/installation).

1. Make tios.zip code archive

   ```bash
   zip -r tios.zip tios/
   ```

1. Deploy the Streamlit App (Stage is created automatically)

   ```bash
   # dev
   snow streamlit deploy STREAMLIT_TIOS_DEV -c tios_dev --file=1_tios_app.py --replace --query-warehouse DEV_WH

   # uat
   snow streamlit deploy STREAMLIT_TIOS_UAT -c tios_uat --file=1_tios_app.py --replace --query-warehouse UAT_WH

   # prod
   snow streamlit deploy STREAMLIT_TIOS -c tios --file=1_tios_app.py --replace --query-warehouse MY_WH
   ```

1. Upload Source Code Archive (`tios.zip`)

   ```bash
   # dev
   snow stage put tios.zip STREAMLIT/STREAMLIT_TIOS_DEV/ --overwrite -c tios_dev

   # uat
   snow stage put tios.zip STREAMLIT/STREAMLIT_TIOS_UAT/ --overwrite -c tios_uat

   # prod
   snow stage put tios.zip STREAMLIT/STREAMLIT_TIOS/ --overwrite -c tios
   ```
