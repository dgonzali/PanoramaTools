# Panorama Security Rules Updater – User Guide

## Description
This script automates the export, review, and update of Security Policy rules from Palo Alto Networks Panorama.

**Main features:**
- Export security rules from a specific Device Group (pre- and post-rulebase).
- Save exported rules in CSV format for review and editing.
- Detect and validate changes between the original and modified CSV files.
- Apply rule updates to Panorama, limited to changes in **Security Profile Group** and **Log Forwarding**.
- Log errors returned by Panorama, including details and timestamps, into a dedicated file.
- Validate that the chosen Security Profile Group and Log Forwarding exist either in the Device Group or in the Shared scope.

## Disclaimer
This script is **NOT** developed, supported, or endorsed by Palo Alto Networks.  
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
- Choose the scope: either the Device Group name or "shared".

  ```
  Select action:
      1) Export rules to CSV
      2) Edit rules from CSV
  Option (1 or 2): 1
  ```
- Select **Export rules** by choosing option 1.

- The rules will be exported to CSV files in the project directory:
   - `panorama_rules_<scope>.csv` (original backup)
   - `panorama_rules_<scope>_modified.csv` (editable for changes)

### Modify Rules
- Open the generated CSV file (`panorama_rules_<scope>_modified.csv`).
- Update **ONLY** the **Security Profile Group** and/or **Log Forwarding** columns as needed.
  - The values must exist in the device or shared scope.
  - If any other field is modified, the script will stop and no changes will be sent.

### Apply Changes
- Save the modified CSV file.
- Run the script again and select **Edit rules** by choosing option 2.

  ```
  Select action:
      1) Export rules to CSV
      2) Edit rules from CSV
  Option (1 or 2): 2
  ```

- Review the detected changes on screen.
- Confirm the update by typing `APPLY`.
- The script will send the changes to Panorama and display a summary.
- Verify the changes in Panorama and commit them.

### Error Handling
- If Panorama rejects a rule update (e.g., non-existent profile group or log forwarding), the script logs the error to a file:

  ```
  error_YYYYMMDD_HHMMSS.log
  ```

- Each log entry includes the rule name, timestamp, and the error message returned by Panorama.

---