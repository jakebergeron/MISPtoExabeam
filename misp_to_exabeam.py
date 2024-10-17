import argparse
import os
import csv
from pymisp import PyMISP
import requests
import json

# Function to authenticate with Exabeam


def authenticate_with_exabeam(exabeam_url):
    api_key = os.getenv("EXABEAM_API_KEY")
    api_secret = os.getenv("EXABEAM_API_SECRET")

    if not api_key or not api_secret:
        print("Exabeam API credentials are not set in the environment.")
        return None

    auth_url = f"{exabeam_url}/auth/v1/token"
    payload = {
        "client_id": api_key,
        "client_secret": api_secret,
        "grant_type": "client_credentials"
    }

    try:
        response = requests.post(
            auth_url,
            headers={
                'Content-Type': 'application/json'},
            data=json.dumps(payload),
            verify=False)
        response.raise_for_status()
        token = response.json().get('access_token')
        print("Authenticated with Exabeam successfully.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error during Exabeam authentication: {e}")
        return None

# Function to get context table ID from Exabeam


def get_context_table_id(token, exabeam_url, table_name):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(
            f"{exabeam_url}/context-management/v1/tables",
            headers=headers,
            verify=False)
        response.raise_for_status()
        tables = response.json()
        for table in tables:
            if table['name'] == table_name:
                print(
                    f"Context table '{table_name}' found with ID: {table['id']}")
                return table['id']
        print(f"Context table '{table_name}' not found.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching context table: {e}")
        return None

# Function to fetch MISP events


def fetch_misp_events(misp_instance):
    try:
        events = misp_instance.search('attributes', type_attribute='ip-src')
        return events
    except Exception as e:
        print(f"Error fetching MISP events: {e}")
        return []

# Function to save IP addresses from MISP to a CSV file


def save_ips_to_csv(events, csv_filename):
    ip_data = []
    for event in events.get('Attribute', []):
        if event['type'] == 'ip-src':
            ip_data.append({'ti_ip_address': event['value']})

    if ip_data:
        with open(csv_filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["ti_ip_address"])
            writer.writeheader()
            writer.writerows(ip_data)
        print(f"IP addresses saved to {csv_filename}")
    else:
        print("No IP addresses found to save.")

# Function to upload CSV to Exabeam context table


def upload_csv_to_exabeam(csv_filename, token, table_id, exabeam_url):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        with open(csv_filename, 'rb') as f:
            response = requests.post(
                f"{exabeam_url}/context-management/v1/tables/{table_id}/addRecordsFromCsv",
                headers=headers,
                files={'file': f},
                data={'operation': 'Replace'},
                verify=False
            )
        response.raise_for_status()
        print(f"CSV file {csv_filename} uploaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading CSV to Exabeam: {e}")

# Main function


def main():
    parser = argparse.ArgumentParser(
        description="MISP to Exabeam Integration Script")
    parser.add_argument("--misp-url", required=True, help="MISP server URL")
    parser.add_argument("--misp-api-key", required=True, help="MISP API key")
    parser.add_argument("--exabeam-url", required=True, help="Exabeam API URL")
    parser.add_argument(
        "--context-table-name",
        required=True,
        help="Name of the Exabeam context table")

    args = parser.parse_args()

    # Connect to MISP
    misp = PyMISP(args.misp_url, args.misp_api_key, False)

    # Authenticate with Exabeam
    token = authenticate_with_exabeam(args.exabeam_url)
    if not token:
        print("Failed to authenticate with Exabeam. Exiting.")
        return

    # Get context table ID from Exabeam
    table_id = get_context_table_id(
        token, args.exabeam_url, args.context_table_name)
    if not table_id:
        print("Failed to retrieve context table ID. Exiting.")
        return

    # Fetch events from MISP
    events = fetch_misp_events(misp)
    if not events:
        print("No events fetched from MISP. Exiting.")
        return

    # Save IP addresses to CSV
    csv_filename = "misp_ip_addresses.csv"
    save_ips_to_csv(events, csv_filename)

    # Upload CSV to Exabeam
    upload_csv_to_exabeam(csv_filename, token, table_id, args.exabeam_url)


if __name__ == '__main__':
    main()
