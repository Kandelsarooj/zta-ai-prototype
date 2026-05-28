# zta.py — Zero Trust Architecture Engine
# Saroj Kandel, MSc Software Engineering, UWL
# Based on NIST SP 800-207 Zero Trust Architecture

TRUSTED_DEVICES = [
    'managed_laptop', 'company_phone', 'office_desktop',
    'managed_tablet', 'corporate_workstation'
]

TRUSTED_LOCATIONS = [
    'London, UK', 'Manchester, UK', 'Birmingham, UK',
    'Edinburgh, UK', 'Bristol, UK', 'Leeds, UK', 'Sheffield, UK'
]

ROLE_PERMISSIONS = {
    'analyst':   ['view_dashboard', 'read_reports', 'view_alerts'],
    'developer': ['view_dashboard', 'read_reports', 'view_alerts', 'access_dev_tools', 'view_logs'],
    'admin':     ['view_dashboard', 'read_reports', 'view_alerts', 'access_dev_tools',
                  'view_logs', 'manage_users', 'system_settings', 'download_files', 'edit_data'],
    'viewer':    ['view_dashboard']
}

def check_identity(username, password, user_data):
    """Check 1 — Verify identity against user directory"""
    if not user_data:
        return False, "Identity verification failed — user not found in trusted directory", None
    from database import hash_password
    if user_data['password_hash'] != hash_password(password):
        return False, "Identity verification failed — incorrect credentials provided", None
    return True, f"Identity verified — welcome {user_data.get('full_name', username)}", user_data['role']

def check_role(role):
    """Check 2 — Verify role and permissions"""
    if not role or role not in ROLE_PERMISSIONS:
        return False, "Role verification failed — no valid role assigned to this account"
    perms = ROLE_PERMISSIONS[role]
    return True, f"Role verified — {role.title()} with {len(perms)} permission(s) assigned"

def check_device(device):
    """Check 3 — Verify device against managed device registry"""
    if device in TRUSTED_DEVICES:
        return True, f"Device verified — '{device}' is a registered managed device"
    return False, f"Device check failed — '{device}' is not in the managed device registry"

def check_location(location):
    """Check 4 — Verify geographic location"""
    if location in TRUSTED_LOCATIONS:
        return True, f"Location verified — '{location}' is within the approved geographic region"
    return False, f"Location check failed — '{location}' is outside approved regions"

def run_zta_checks(username, password, device, location, user_data=None):
    results = {
        'passed': False, 'role': None, 'message': '',
        'checks': {
            'identity': {'passed': False, 'message': '', 'icon': 'user'},
            'role':     {'passed': False, 'message': '', 'icon': 'shield'},
            'device':   {'passed': False, 'message': '', 'icon': 'monitor'},
            'location': {'passed': False, 'message': '', 'icon': 'map-pin'}
        }
    }

    # Check 1 — Identity
    ok, msg, role = check_identity(username, password, user_data)
    results['checks']['identity'] = {'passed': ok, 'message': msg, 'icon': 'user'}
    if not ok:
        results['message'] = msg
        return results

    # Check 2 — Role
    ok2, msg2 = check_role(role)
    results['checks']['role'] = {'passed': ok2, 'message': msg2, 'icon': 'shield'}
    if not ok2:
        results['message'] = msg2
        return results

    # Check 3 — Device
    ok3, msg3 = check_device(device)
    results['checks']['device'] = {'passed': ok3, 'message': msg3, 'icon': 'monitor'}
    if not ok3:
        results['message'] = msg3
        return results

    # Check 4 — Location
    ok4, msg4 = check_location(location)
    results['checks']['location'] = {'passed': ok4, 'message': msg4, 'icon': 'map-pin'}
    if not ok4:
        results['message'] = msg4
        return results

    results['passed'] = True
    results['role'] = role
    results['permissions'] = ROLE_PERMISSIONS.get(role, [])
    results['message'] = f"All Zero Trust checks passed — access pipeline initiated for {username}"
    return results
