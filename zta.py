# zta.py
# Author: Saroj Kandel — MSc Software Engineering, UWL
# Purpose: Zero Trust Architecture access control — 4 checks, all must pass

TRUSTED_USERS = {
    'alice': {'password': 'alice123', 'role': 'analyst',   'email': 'alice@company.com'},
    'bob':   {'password': 'bob123',   'role': 'developer', 'email': 'bob@company.com'},
    'carol': {'password': 'carol123', 'role': 'admin',     'email': 'carol@company.com'},
    'dave':  {'password': 'dave123',  'role': 'analyst',   'email': 'dave@company.com'},
}

TRUSTED_DEVICES = ['managed_laptop','company_phone','office_desktop','managed_tablet']

TRUSTED_LOCATIONS = ['London, UK','Manchester, UK','Birmingham, UK','Edinburgh, UK','Bristol, UK']

ROLE_PERMISSIONS = {
    'analyst':   ['read_reports','view_dashboard'],
    'developer': ['read_reports','view_dashboard','access_dev_tools'],
    'admin':     ['read_reports','view_dashboard','access_dev_tools','manage_users','system_settings']
}

def check_identity(username, password):
    if username not in TRUSTED_USERS:
        return False, "Unknown user — not in trusted directory"
    if TRUSTED_USERS[username]['password'] != password:
        return False, "Incorrect password — identity not verified"
    return True, "Identity verified successfully"

def check_role(username):
    if username not in TRUSTED_USERS:
        return False, None, "No role assigned — user unknown"
    role = TRUSTED_USERS[username]['role']
    if role not in ROLE_PERMISSIONS:
        return False, role, "Role not recognised in permission system"
    return True, role, f"Role verified: {role}"

def check_device(device):
    if device in TRUSTED_DEVICES:
        return True, "Device is trusted and managed"
    return False, f"Untrusted device: {device} — not in managed device registry"

def check_location(location):
    if location in TRUSTED_LOCATIONS:
        return True, "Location is within trusted region"
    return False, f"Untrusted location: {location} — outside approved regions"

def run_zta_checks(username, password, device, location):
    results = {
        'passed': False, 'role': None, 'message': '',
        'checks': {
            'identity': {'passed': False, 'message': ''},
            'role':     {'passed': False, 'message': ''},
            'device':   {'passed': False, 'message': ''},
            'location': {'passed': False, 'message': ''}
        }
    }
    id_ok, id_msg = check_identity(username, password)
    results['checks']['identity'] = {'passed': id_ok, 'message': id_msg}
    if not id_ok:
        results['message'] = f"ZTA DENIED — Identity check failed: {id_msg}"
        return results

    role_ok, role, role_msg = check_role(username)
    results['checks']['role'] = {'passed': role_ok, 'message': role_msg}
    if not role_ok:
        results['message'] = f"ZTA DENIED — Role check failed: {role_msg}"
        return results

    dev_ok, dev_msg = check_device(device)
    results['checks']['device'] = {'passed': dev_ok, 'message': dev_msg}
    if not dev_ok:
        results['message'] = f"ZTA DENIED — Device check failed: {dev_msg}"
        return results

    loc_ok, loc_msg = check_location(location)
    results['checks']['location'] = {'passed': loc_ok, 'message': loc_msg}
    if not loc_ok:
        results['message'] = f"ZTA DENIED — Location check failed: {loc_msg}"
        return results

    results['passed']  = True
    results['role']    = role
    results['message'] = f"ZTA PASSED — All 4 checks verified for {username}"
    return results
