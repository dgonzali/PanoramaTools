# PanoramaTools

PanoramaTools is a collection of scripts designed to help automate tasks in **Palo Alto Networks Panorama**, such as pushing configurations, committing changes, and checking synchronization status of managed devices.  

⚠️ **Disclaimer:** This project is provided *as is*, with **no warranty or official support**. Use it at your own risk.  

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dgonzali/PanoramaTools.git
   cd PanoramaTools

   ```bash
   pip install -r requirements.txt

▶️ Usage
Run the script from the project folder:

   ```bash
   python script_name.py
   Replace script_name.py with the specific script you want to run.

Some scripts may require arguments or configuration (such as Panorama API credentials, device groups, or template names). Refer to the comments 

inside each script for usage details.

▶️ How it works
-------------
1. Export rules from a Device Group or shared policy into CSV files:
   - panorama_rules_<scope>.csv (original backup)
   - panorama_rules_<scope>_modified.csv (editable for profile_group changes)
2. Detect differences between the original CSV and the modified CSV.
3. Only allow modifications to the profile_group field. Any other change aborts the script.
4. Update rules in Panorama, preserving all other fields.
5. For rules that fail to update, generate an error log file named:
   error_<YYYYMMDD_HHMMSS>.log, containing exact API error messages.



