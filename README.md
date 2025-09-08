# Panorama Security Rules Updater – User Guide

## Description
This script automates the export, review, and update of Security Policy rules from Palo Alto Networks Panorama.  
Its main features are:

- Export security rules from a specific Device Group (pre- and post-rulebase).
- Save the exported rules in CSV format for review and editing.
- Detect and validate changes between the original and modified CSVs.
- Apply rule updates to Panorama, limited to changes in the Security Profile Group.
- Log errors returned by Panorama, including details and timestamps, into a dedicated file.
- Validate that the chosen Security Profile Group exists either in the Device Group or in the Shared scope.

## Disclaimer
This script is not developed, supported, or endorsed by Palo Alto Networks.  
Use it at your own risk. No official support is provided.

## How to Use the Script (Example with Visual Studio Code)

### Preparation
- Install Python 3.9+ on your workstation.
- Clone or download the repository containing the script.
- Install required dependencies from the provided requirements.txt:

  ```bash
  pip install -r requirements.txt
  ```

### Configure Panorama Access
- Edit the `config.json` file in the project folder.
- Replace the placeholders with your Panorama IP/FQDN and valid API key:

  ```json
  {
    "panorama_host": "https://192.168.1.10",
    "api_key": "YOUR_API_KEY"
  }
  ```

### Export Rules
- Open the project in Visual Studio Code.
- Run the script:

  ```bash
  python panorama_rules.py
  ```

- Select **Export rules** and choose the desired Device Group.
- The rules will be exported to CSV files in the project directory (e.g. `panorama_rules_<DG>.csv`).

### Modify Rules
- Open the generated CSV file.
- Update only the **Security Profile Group** column as needed.
- All other fields must remain unchanged.

### Apply Changes
- Save the modified CSV file (same filename with `_modified`).
- Run the script again and select **Edit rules**.
- Review the detected changes on screen.
- Confirm the update by typing `APPLY`.
- The script will push the changes to Panorama and display a summary.

### Error Handling
- If Panorama rejects a rule update (e.g., non-existent profile group), the script logs the error to a file:

  ```
  error_YYYYMMDD_HHMMSS.log
  ```

- Each log entry includes the rule name, timestamp, and the error message returned by Panorama.

---

*Tip: Add screenshots here to illustrate the steps if using Visual Studio Code.*
