import requests
import csv
import xml.etree.ElementTree as ET
import json
import sys

"""
Bulk Security Rule Management for Palo Alto Networks Panorama (Unofficial Tool)

Description:
------------
This script automates the **bulk editing and updating of security policy rules** on a Palo Alto Networks Panorama system via its XML API.
It is designed to apply consistent changes across many rules simultaneously, significantly reducing the time and risk associated with manual editing in the Panorama GUI.

Main Features:
--------------
1. Export Security Rules:
   - Retrieves both "pre-rulebase" and "post-rulebase" rules from a specified Device Group or from shared policies.
   - Saves a snapshot of all rules into a CSV file (`panorama_rules_<scope>.csv`) as a backup.
   - Creates a second editable file (`panorama_rules_<scope>_modified.csv`) intended for bulk changes.

2. Compare and Apply Rule Changes:
   - Compares the modified file with the original.
   - Identifies and summarizes changes (added or modified rules).
   - Asks for user confirmation before applying changes via API.
   - Note: Rule deletions are detected but not applied.

Backup & Best Practices:
------------------------
- The original CSV file is **never overwritten** and acts as a reliable backup.
- It is **strongly recommended to save the original CSV externally** before applying changes, for rollback purposes if needed.

Usage:
------
1. Create a `config.json` file with your Panorama host and API key:
   {
       "panorama_host": "https://<your-panorama-host>",
       "api_key": "<your-api-key>"
   }

2. Run the script:
   python script.py

3. Follow the prompts:
   - Option 1: Export rules from a Device Group or from shared policies.
   - Option 2: Edit the `_modified.csv` file and apply the changes.

Technical Notes:
----------------
- Based on Python 3.x
- Uses Python's `xml.etree.ElementTree` for XML processing.
- HTTPS certificate verification is disabled (`verify=False`).

Disclaimer:
-----------
- This script has not been developed by Palo Alto Networks.
- It is not officially supported and comes with no warranty or guarantee.
- Use it at your own risk, and always validate changes before committing them in production environments.
"""

# ----------- Load config ----------- #
with open('config.json') as f:
    config = json.load(f)

PANORAMA_HOST = config['panorama_host']
API_KEY = config['api_key']

requests.packages.urllib3.disable_warnings()

# ----------- Funciones comunes ----------- #

def get_security_rules(host, api_key, policy_scope, rulebase_type):
    """
    policy_scope puede ser un device group o 'shared'
    """
    if rulebase_type not in ['pre', 'post']:
        raise ValueError("rulebase_type debe ser 'pre' o 'post'")
    url = f"{host}/api/"
    if policy_scope.lower() == 'shared':
        xpath = f"/config/shared/{rulebase_type}-rulebase/security/rules"
    else:
        # asumo que es device group
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{policy_scope}']/{rulebase_type}-rulebase/security/rules"

    params = {
        'type': 'config',
        'action': 'get',
        'key': api_key,
        'xpath': xpath
    }

    response = requests.get(url, params=params, verify=False)
    if response.status_code != 200:
        raise Exception(f"Error obteniendo reglas {rulebase_type} de {policy_scope}: {response.status_code} {response.text}")
    return response.text

def parse_rules(xml_data, rulebase_type):
    rules = []
    root = ET.fromstring(xml_data)
    for rule in root.findall(".//entry"):
        rule_dict = {
            'rulebase_type': rulebase_type,
            'name': rule.get('name', ''),
            'description': rule.findtext('description', ''),
            'from': ' '.join([x.text for x in rule.findall('from/member')]),
            'to': ' '.join([x.text for x in rule.findall('to/member')]),
            'source': ' '.join([x.text for x in rule.findall('source/member')]),
            'destination': ' '.join([x.text for x in rule.findall('destination/member')]),
            'application': ' '.join([x.text for x in rule.findall('application/member')]),
            'service': ' '.join([x.text for x in rule.findall('service/member')]),
            'action': rule.findtext('action', ''),
            'disabled': rule.findtext('disabled', 'no'),
            'profile_group': ' '.join([x.text for x in rule.findall('profile-setting/group/member')]),
            'virus': rule.findtext('profile-setting/virus', ''),
            'spyware': rule.findtext('profile-setting/spyware', ''),
            'vulnerability': rule.findtext('profile-setting/vulnerability', ''),
            'url_filtering': rule.findtext('profile-setting/url-filtering', ''),
            'file_blocking': rule.findtext('profile-setting/file-blocking', ''),
            'wildfire_analysis': rule.findtext('profile-setting/wildfire-analysis', ''),
            'data_filtering': rule.findtext('profile-setting/data-filtering', ''),
            'log_start': rule.findtext('log-start', 'no'),
            'log_end': rule.findtext('log-end', 'no'),
            'log_setting': rule.findtext('log-setting', '')
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
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule)

def read_csv_rules(filename):
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

# --- Funciones para edición y comparación (igual que antes) ---

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

def build_profile_setting_element(rule):
    ps = ET.Element('profile-setting')
    group_text = rule.get('profile_group', '').strip()
    if group_text:
        group = ET.SubElement(ps, 'group')
        for member in split_members(group_text):
            m = ET.SubElement(group, 'member')
            m.text = member
    profile_fields = ['virus', 'spyware', 'vulnerability', 'url_filtering',
                      'file_blocking', 'wildfire_analysis', 'data_filtering']
    for pf in profile_fields:
        val = rule.get(pf, '').strip()
        if val:
            elem = ET.SubElement(ps, pf)
            elem.text = val
    return ps

def build_rule_entry_xml(rule):
    entry = ET.Element('entry', attrib={'name': rule['name']})
    for tag, key in [('action', 'action'), ('disabled', 'disabled')]:
        val = rule.get(key, '').strip()
        if tag == 'disabled':
            val = bool_to_yesno(val)
        if val:
            e = ET.SubElement(entry, tag)
            e.text = val
    for tag, key in [('log-start', 'log_start'), ('log-end', 'log_end')]:
        val = bool_to_yesno(rule.get(key, 'no'))
        e = ET.SubElement(entry, tag)
        e.text = val
    log_setting = rule.get('log_setting', '').strip()
    if log_setting:
        e = ET.SubElement(entry, 'log-setting')
        e.text = log_setting
    multi_fields = ['from', 'to', 'source', 'destination', 'application', 'service']
    for field in multi_fields:
        values = split_members(rule.get(field, ''))
        if values:
            parent = ET.SubElement(entry, field)
            for val in values:
                m = ET.SubElement(parent, 'member')
                m.text = val
    profile_setting = build_profile_setting_element(rule)
    if len(profile_setting):
        entry.append(profile_setting)
    return entry

def update_rule(panorama_host, api_key, policy_scope, rulebase_type, rule):
    url = f"{panorama_host}/api/"
    entry_xml = build_rule_entry_xml(rule)
    entry_str = ET.tostring(entry_xml, encoding='unicode')
    if policy_scope.lower() == 'shared':
        xpath = (
            f"/config/shared/{rulebase_type}-rulebase/security/rules/entry[@name='{rule['name']}']"
        )
    else:
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{policy_scope}']/"
            f"{rulebase_type}-rulebase/security/rules/entry[@name='{rule['name']}']"
        )
    params = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': entry_str
    }
    response = requests.post(url, params=params, verify=False)
    if response.status_code == 200:
        xml_resp = ET.fromstring(response.text)
        status = xml_resp.attrib.get('status', '')
        if status == 'success':
            print(f"✅ Regla '{rule['name']}' actualizada correctamente.")
            return True
        else:
            print(f"[ERROR] Actualizando regla '{rule['name']}' falló:")
            print(response.text)
            return False
    else:
        print(f"[ERROR] HTTP error actualizando regla '{rule['name']}': {response.status_code}")
        return False

def normalize_rule(rule):
    normalized = {}
    bool_fields = ['disabled', 'log_start', 'log_end']
    list_fields = ['from', 'to', 'source', 'destination', 'application', 'service', 'profile_group']
    for k,v in rule.items():
        v = v.strip() if isinstance(v, str) else v
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
        v = rule.get(pf, '').strip()
        normalized[pf] = v
    normalized['name'] = rule.get('name','').strip()
    normalized['rulebase_type'] = rule.get('rulebase_type','').strip().lower()
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

def show_changes_summary_with_diff(diffs):
    print("\nSe detectaron los siguientes cambios en reglas:\n")
    for idx, (key, diff_data) in enumerate(diffs.items(), 1):
        action = diff_data[0]
        orig = diff_data[1]
        mod = diff_data[2]
        print(f"{idx}. Regla '{key[0]}' ({key[1].upper()}): {action}")
        if action == 'Modified':
            changed_fields = diff_data[3]
            for field, (old_val, new_val) in changed_fields.items():
                print(f"    - Campo '{field}':")
                print(f"        Antes: '{old_val}'")
                print(f"        Después: '{new_val}'")
        elif action == 'Deleted':
            print("    - La regla será eliminada (no implementado en update, solo aviso).")
        elif action == 'Added':
            print("    - La regla será añadida.")
    print(f"\nTotal reglas con cambios: {len(diffs)}")
    print("Escribe 'APPLY' para confirmar la actualización o cualquier otra cosa para cancelar:")

# ----------- Menu e integración ----------- #

def export_rules(policy_scope):
    print(f"Exportando reglas de {policy_scope} ...")
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
    print(f" 📝 Exportación completada, reglas guardadas en '{filename}'")

    modified_filename = f"panorama_rules_{policy_scope}_modified.csv"
    write_csv(all_rules, modified_filename)
 
    print(f" 📝 Se ha creado también '{modified_filename}'.")
    print(f" ")
    print(f" ➡️  Para modificar reglas, edita UNICAMENTE el archivo '{modified_filename}' y posteriormente usa la opción de editar reglas.")

def edit_rules(policy_scope):
    print(f"Preparando actualización de reglas para {policy_scope} ...")
    original_file = f"panorama_rules_{policy_scope}.csv"
    modified_file = f"panorama_rules_{policy_scope}_modified.csv"

    try:
        original_rules = read_csv_rules(original_file)
    except Exception as e:
        print(f"[ERROR] No se pudo leer archivo original '{original_file}': {e}")
        return
    try:
        modified_rules = read_csv_rules(modified_file)
    except Exception as e:
        print(f"[ERROR] No se pudo leer archivo modificado '{modified_file}': {e}")
        return

    dict_original = rules_to_dict(original_rules)
    dict_modified = rules_to_dict(modified_rules)
    diffs = diff_rules(dict_original, dict_modified)
    diffs_to_apply = {k: v for k,v in diffs.items() if v[0] in ('Modified', 'Added')}

    if not diffs_to_apply:
        print("No hay cambios detectados que requieran actualización.")
        return

    show_changes_summary_with_diff(diffs_to_apply)

    user_input = input().strip()
    if user_input != "APPLY":
        print("Actualización cancelada por el usuario.")
        return

    print("\nActualizando reglas...")
    for key, diff_data in diffs_to_apply.items():
        action = diff_data[0]
        mod_rule = diff_data[2]
        rulebase_type = mod_rule.get('rulebase_type', '').lower()
        if rulebase_type not in ['pre', 'post']:
            print(f"[WARN] Regla '{mod_rule.get('name','')}' con rulebase_type inválido: '{rulebase_type}', se omite.")
            continue
        update_rule(PANORAMA_HOST, API_KEY, policy_scope, rulebase_type, mod_rule)

    print("✅ Actualización finalizada.")

def main_menu():
    print("==== Gestión de reglas PAN-OS Panorama ====\n")
    policy_scope = input("Introduce el nombre del Device Group o 'shared' para políticas compartidas: ").strip()
    if not policy_scope:
        print("[ERROR] Debes introducir un Device Group válido o 'shared'")
        sys.exit(1)

    print("\nSelecciona la acción a realizar:")
    print("  1) Exportar reglas a CSV")
    print("  2) Editar reglas desde CSV")
    option = input("Opción (1 o 2): ").strip()

    if option == '1':
        export_rules(policy_scope)
    elif option == '2':
        edit_rules(policy_scope)
    else:
        print("[ERROR] Opción no válida. Saliendo.")
        sys.exit(1)

if __name__ == "__main__":
    main_menu()
