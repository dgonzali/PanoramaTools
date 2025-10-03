import requests
import csv
import xml.etree.ElementTree as ET
import json
import sys
import datetime

"""
Bulk Security Rule Management for Palo Alto Networks Panorama
(Supports profile_group and log_setting edits; preserves all other fields)

Description:
------------
This script automates the bulk editing of security rules on a Palo Alto Networks Panorama system
via its XML API. It is restricted to updating **only the Security Profile Group (profile_group) 
and the Log Forwarding Profile (log_setting)**. All other fields in the rule are preserved.

How it works:
-------------
1. Export rules from a Device Group or shared policy into CSV files:
   - panorama_rules_<scope>.csv (original backup)
   - panorama_rules_<scope>_modified.csv (editable for profile_group/log_setting changes)
2. Detect differences between the original CSV and the modified CSV.
3. Only allow modifications to the profile_group and log_setting fields. Any other change aborts the script.
4. Update rules in Panorama, preserving all other fields.
5. For rules that fail to update, generate an error log file named:
   error_<YYYYMMDD_HHMMSS>.log, containing exact API error messages.

Disclaimer:
-----------
- Not developed by Palo Alto Networks.
- Not officially supported. Use at your own risk.
"""

# ----------- Load config ----------- #
with open('config.json') as f:
    config = json.load(f)

PANORAMA_HOST = config['panorama_host']
API_KEY = config['api_key']

requests.packages.urllib3.disable_warnings()

# ----------- Utilities ----------- #
def clean_text(value):
    if not isinstance(value, str):
        return value
    return ' '.join(value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').split())

def sanitize_row_for_csv(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        out[k] = clean_text(v) if isinstance(v, str) else v
    return out

# ----------- API / parsing helpers ----------- #
def get_security_rules(host, api_key, policy_scope, rulebase_type):
    if rulebase_type not in ['pre', 'post']:
        raise ValueError("rulebase_type must be 'pre' or 'post'")
    url = f"{host}/api/"
    if policy_scope.lower() == 'shared':
        xpath = f"/config/shared/{rulebase_type}-rulebase/security/rules"
    else:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{policy_scope}']/{rulebase_type}-rulebase/security/rules"

    params = {'type': 'config', 'action': 'get', 'key': api_key, 'xpath': xpath}
    response = requests.get(url, params=params, verify=False)
    if response.status_code != 200:
        raise Exception(f"Error retrieving {rulebase_type} rules from {policy_scope}: {response.status_code} {response.text}")
    return response.text

def _join_members(elems):
    vals = []
    for x in elems:
        if x.text is not None:
            vals.append(clean_text(x.text))
    return ' '.join([v for v in vals if v])

def parse_rules(xml_data, rulebase_type):
    rules = []
    root = ET.fromstring(xml_data)
    for rule in root.findall(".//entry"):
        rule_dict = {
            'rulebase_type': clean_text(rulebase_type),
            'name': clean_text(rule.get('name', '')),
            'description': clean_text(rule.findtext('description', '')),
            'from': _join_members(rule.findall('from/member')),
            'to': _join_members(rule.findall('to/member')),
            'source': _join_members(rule.findall('source/member')),
            'destination': _join_members(rule.findall('destination/member')),
            'application': _join_members(rule.findall('application/member')),
            'service': _join_members(rule.findall('service/member')),
            'action': clean_text(rule.findtext('action', '')),
            'disabled': clean_text(rule.findtext('disabled', 'no')),
            'profile_group': _join_members(rule.findall('profile-setting/group/member')),
            'virus': clean_text(rule.findtext('profile-setting/virus', '')),
            'spyware': clean_text(rule.findtext('profile-setting/spyware', '')),
            'vulnerability': clean_text(rule.findtext('profile-setting/vulnerability', '')),
            'url_filtering': clean_text(rule.findtext('profile-setting/url-filtering', '')),
            'file_blocking': clean_text(rule.findtext('profile-setting/file-blocking', '')),
            'wildfire_analysis': clean_text(rule.findtext('profile-setting/wildfire-analysis', '')),
            'data_filtering': clean_text(rule.findtext('profile-setting/data-filtering', '')),
            'log_start': clean_text(rule.findtext('log-start', 'no')),
            'log_end': clean_text(rule.findtext('log-end', 'no')),
            'log_setting': clean_text(rule.findtext('log-setting', ''))
        }
        rules.append(rule_dict)
    return rules

def write_csv(rules, filename):
    fieldnames = [
        'rulebase_type', 'name', 'description', 'from', 'to', 'source', 'destination',
        'application', 'service', 'action', 'disabled',
        'profile_group', 'virus', 'spyware', 'vulnerability',
        'url_filtering', 'file_blocking', 'wildfire_analysis', 'data_filtering',
        'log_start', 'log_end', 'log_setting'
    ]
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, lineterminator='\n')
        writer.writeheader()
        for rule in rules:
            writer.writerow(sanitize_row_for_csv(rule))

def read_csv_rules(filename):
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return [sanitize_row_for_csv(r) for r in reader]

def bool_to_yesno(value):
    if isinstance(value, str):
        val = value.strip().lower()
        if val in ['yes', 'true', '1']:
            return 'yes'
    return 'no'

def split_members(field_value):
    if not field_value:
        return []
    return [m.strip() for m in field_value.split() if m.strip()]

# ----------- Get and update full rule entry ----------- #
def get_rule_entry_element(panorama_host, api_key, policy_scope, rulebase_type, rule_name):
    url = f"{panorama_host}/api/"
    if policy_scope.lower() == 'shared':
        xpath = f"/config/shared/{rulebase_type}-rulebase/security/rules/entry[@name='{rule_name}']"
    else:
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{policy_scope}']/"
            f"{rulebase_type}-rulebase/security/rules/entry[@name='{rule_name}']"
        )
    params = {'type': 'config', 'action': 'get', 'key': api_key, 'xpath': xpath}
    response = requests.get(url, params=params, verify=False)
    if response.status_code != 200:
        raise Exception(f"Error retrieving rule '{rule_name}': {response.status_code} {response.text}")
    root = ET.fromstring(response.text)
    entry = root.find('.//entry')
    return entry, xpath

def update_rule(panorama_host, api_key, policy_scope, rulebase_type, rule):
    url = f"{panorama_host}/api/"
    name = rule.get('name', '')
    try:
        entry_elem, xpath_entry = get_rule_entry_element(panorama_host, api_key, policy_scope, rulebase_type, name)
    except Exception as e:
        print(f"[ERROR] Could not retrieve original entry for rule '{name}': {e}")
        return False, str(e)

    if entry_elem is None:
        msg = f"Rule '{name}' not found in Panorama (scope={policy_scope}, type={rulebase_type})."
        print(f"[ERROR] {msg}")
        return False, msg

    # --- profile-group update ---
    ps = entry_elem.find('profile-setting')
    if ps is None:
        ps = ET.Element('profile-setting')
        entry_elem.append(ps)

    existing_group = ps.find('group')
    if existing_group is not None:
        ps.remove(existing_group)

    group_text = rule.get('profile_group', '').strip()
    if group_text:
        group = ET.SubElement(ps, 'group')
        for member in split_members(group_text):
            m = ET.SubElement(group, 'member')
            m.text = member

    # --- log-setting update ---
    existing_log = entry_elem.find('log-setting')
    if existing_log is not None:
        entry_elem.remove(existing_log)

    log_text = rule.get('log_setting', '').strip()
    if log_text:
        log_elem = ET.SubElement(entry_elem, 'log-setting')
        log_elem.text = log_text

    entry_str = ET.tostring(entry_elem, encoding='unicode')
    params = {'type': 'config', 'action': 'edit', 'key': api_key, 'xpath': xpath_entry, 'element': entry_str}
    response = requests.post(url, params=params, verify=False)

    if response.status_code == 200:
        try:
            xml_resp = ET.fromstring(response.text)
            status = xml_resp.attrib.get('status', '')
            if status == 'success':
                print(f"✅ Rule '{name}' updated successfully (profile_group/log_setting updated).")
                return True, ""
            else:
                print(f"[ERROR] Panorama returned error updating '{name}':")
                print(response.text)
                return False, response.text
        except ET.ParseError:
            print(f"[ERROR] Non-XML response updating rule '{name}': {response.text}")
            return False, response.text
    else:
        msg = f"HTTP error updating rule '{name}': {response.status_code}"
        print(f"[ERROR] {msg}")
        return False, msg

# ----------- Normalization & comparison ----------- #
def normalize_rule(rule):
    normalized = {}
    bool_fields = ['disabled', 'log_start', 'log_end']
    list_fields = ['from', 'to', 'source', 'destination', 'application', 'service', 'profile_group']
    for k, v in rule.items():
        v = clean_text(v) if isinstance(v, str) else v
        if k in bool_fields:
            normalized[k] = bool_to_yesno(v)
        elif k in list_fields:
            members = split_members(v)
            normalized[k] = ' '.join(sorted(members))
        else:
            normalized[k] = v
    profile_fields = ['virus', 'spyware', 'vulnerability', 'url_filtering',
                      'file_blocking', 'wildfire_analysis', 'data_filtering']
    for pf in profile_fields:
        v = clean_text(rule.get(pf, ''))
        normalized[pf] = v
    normalized['name'] = clean_text(rule.get('name', ''))
    normalized['rulebase_type'] = rule.get('rulebase_type', '').strip().lower()
    return normalized

def rules_to_dict(rules_list):
    d = {}
    for r in rules_list:
        nr = normalize_rule(r)
        key = (nr['name'], nr['rulebase_type'])
        d[key] = nr
    return d

def diff_rules(orig, mod):
    diffs = {}
    for key in orig.keys():
        o = orig[key]
        m = mod.get(key)
        if m is None:
            diffs[key] = ('Deleted', o, None)
        elif o != m:
            changed_fields = {}
            for field in o.keys():
                if o[field] != m.get(field, None):
                    changed_fields[field] = (o[field], m.get(field, None))
            diffs[key] = ('Modified', o, m, changed_fields)
    for key in mod.keys():
        if key not in orig:
            diffs[key] = ('Added', None, mod[key])
    return diffs

def validate_allowed_changes(diffs):
    allowed_fields = ['profile_group', 'log_setting']
    for key, diff_data in diffs.items():
        action = diff_data[0]
        if action == 'Modified':
            changed_fields = diff_data[3]
            for field in changed_fields.keys():
                if field not in allowed_fields:
                    print(f"\n[ERROR] Only {allowed_fields} can be modified.")
                    print(f"Detected change in rule '{key[0]}' (field: '{field}')")
                    sys.exit(1)
        elif action in ['Added', 'Deleted']:
            print(f"\n[ERROR] Adding or deleting rules is not allowed.")
            print(f"Detected in rule '{key[0]}' ({action}).")
            sys.exit(1)

def show_changes_summary_with_diff(diffs):
    print("\nDetected changes in rules:\n")
    for idx, (key, diff_data) in enumerate(diffs.items(), 1):
        action = diff_data[0]
        orig = diff_data[1]
        mod = diff_data[2]
        print(f"{idx}. Rule '{key[0]}' ({key[1].upper()}): {action}")
        if action == 'Modified':
            changed_fields = diff_data[3]
            for field, (old_val, new_val) in changed_fields.items():
                print(f"    - Field '{field}':")
                print(f"        Before: '{old_val}'")
                print(f"        After: '{new_val}'")
    print(f"\nTotal rules with changes: {len(diffs)}")
    print("Type 'APPLY' to confirm update or anything else to cancel:")

# ----------- Export / Edit functions ----------- #
def export_rules(policy_scope):
    print(f"Exporting rules from {policy_scope} ...")
    all_rules = []
    for rulebase_type in ['pre', 'post']:
        try:
            xml_data = get_security_rules(PANORAMA_HOST, API_KEY, policy_scope, rulebase_type)
            rules = parse_rules(xml_data, rulebase_type)
            all_rules.extend(rules)
        except Exception as e:
            print(f"[ERROR] {e}")
            return
    filename = f"panorama_rules_{policy_scope}.csv"
    write_csv(all_rules, filename)
    print(f" 📝 Export completed, saved in '{filename}'")

    modified_filename = f"panorama_rules_{policy_scope}_modified.csv"
    write_csv(all_rules, modified_filename)
    print(f" 📝 Also created '{modified_filename}' for editing profile_group and log_setting only.")

def edit_rules(policy_scope):
    print(f"Preparing rule update for {policy_scope} ...")
    original_file = f"panorama_rules_{policy_scope}.csv"
    modified_file = f"panorama_rules_{policy_scope}_modified.csv"

    try:
        original_rules = read_csv_rules(original_file)
    except Exception as e:
        print(f"[ERROR] Could not read original file '{original_file}': {e}")
        return
    try:
        modified_rules = read_csv_rules(modified_file)
    except Exception as e:
        print(f"[ERROR] Could not read modified file '{modified_file}': {e}")
        return

    dict_original = rules_to_dict(original_rules)
    dict_modified = rules_to_dict(modified_rules)
    diffs = diff_rules(dict_original, dict_modified)
    diffs_to_apply = {k: v for k, v in diffs.items() if v[0] in ('Modified',)}

    if not diffs_to_apply:
        print("No changes detected that require update.")
        return

    validate_allowed_changes(diffs_to_apply)
    show_changes_summary_with_diff(diffs_to_apply)

    user_input = input().strip()
    if user_input != "APPLY":
        print("Update cancelled by user.")
        return

    print("\nUpdating rules...")
    success = 0
    failed = 0
    error_entries = []

    for key, diff_data in diffs_to_apply.items():
        mod_rule = diff_data[2]
        rulebase_type = mod_rule.get('rulebase_type', '').lower()
        if rulebase_type not in ['pre', 'post']:
            print(f"[WARN] Rule '{mod_rule.get('name','')}' has invalid rulebase_type '{rulebase_type}', skipping.")
            continue
        ok, msg = update_rule(PANORAMA_HOST, API_KEY, policy_scope, rulebase_type, mod_rule)
        if ok:
            success += 1
        else:
            failed += 1
            error_entries.append((mod_rule.get('name',''), rulebase_type, msg))

    # Log errors if any
    if failed > 0:
        timestamp_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"error_{timestamp_file}.log"
        with open(log_filename, 'w', encoding='utf-8') as f:
            f.write(f"Errors updating rules in {policy_scope}:\n\n")
            for rule_name, rule_type, msg in error_entries:
                timestamp_line = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp_line}] Rule: {rule_name} ({rule_type.upper()})\n")
                f.write(f"[{timestamp_line}] Error: {msg}\n\n")
        print(f"❌ {failed} rules failed. See '{log_filename}' for details.")

    if failed == 0:
        print("✅ Update completed successfully.")
    else:
        print("⚠️ Update finished with errors. Check log file for details.")

# ----------- Main menu ----------- #
def main_menu():
    print("==== PAN-OS Panorama Rule Management ====\n")
    policy_scope = input("Enter Device Group name or 'shared' for shared policies: ").strip()
    if not policy_scope:
        print("[ERROR] You must enter a valid Device Group or 'shared'")
        sys.exit(1)

    print("\nSelect action:")
    print("  1) Export rules to CSV")
    print("  2) Edit rules from CSV")
    option = input("Option (1 or 2): ").strip()

    if option == '1':
        export_rules(policy_scope)
    elif option == '2':
        edit_rules(policy_scope)
    else:
        print("[ERROR] Invalid option. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main_menu()
