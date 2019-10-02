#!/usr/bin/python -O
# (C) Copyright WALLIX S.A. 2019

import sys
import json
import requests
from tempfile import TemporaryFile 
import argparse
import getpass
import urllib3
from urllib.parse import urlencode, urljoin
import uuid
from datetime import datetime

_domain_type_labels = { "local" : "Device", "global" : "Global"}

_accounts = {}
_devices = {}
_jump_server_farms = {}
_applications = {}
_services = {}
_services_alias = {}
_service_ids = {}
_device_ids = {}
_account_ids = {}
_connection_policies = {
    "RAWTCPIP": {
        "connection_policy_name": "RAWTCPIP",
        "protocol": "RAWTCPIP",
        "is_default": True
    },
    "RDP": {
        "connection_policy_name": "RDP",
        "protocol": "RDP",
        "is_default": True
    },
    "RLOGIN": {
        "connection_policy_name": "RLOGIN",
        "protocol": "RLOGIN",
        "is_default": True
    },
    "SSH": {
        "connection_policy_name": "SSH",
        "protocol": "SSH",
        "is_default": True
    },
    "TELNET": {
        "connection_policy_name": "TELNET",
        "protocol": "TELNET",
        "is_default": True
    },
    "VNC": {
        "connection_policy_name": "VNC",
        "protocol": "VNC",
        "is_default": True
    }
}
_connection_policy_ids = {"RAWTCPIP":"RAWTCPIP", "RDP":"RDP", "RLOGIN":"RLOGIN", "SSH":"SSH", "TELNET":"TELNET", "VNC":"VNC"}
_external_auths = {}
_directory_server_ids = {}
_directories = {}
_directory_ids = {}
_user_groups = {}
_user_group_ids = {}
_user_group_mappings = {}
_target_groups = {}
_target_group_ids = {}
_authorizations = {}
_authorization_ids = {}
_account_targets = {}
_account_target_ids = {}
_account_mapping_targets = {}
_account_mapping_target_ids = {}
_interactive_login_targets = {}
_interactive_login_target_ids = {}
_scenario_account_targets = {}
_scenario_account_target_ids = {}
_app_account_targets = {}
_app_account_target_ids = {}
_app_account_mapping_targets = {}
_app_account_mapping_target_ids = {}
_app_interactive_login_targets = {}
_app_interactive_login_target_ids = {}
_application_ids = {}
_jump_server_farm_ids = {}
_jump_server_farm_targets = {}

_credential_recovery = False

_uuids = []

class Based:
    """
    Mix-in for a requests Session where the URL may be relative to
    a base for the session.
    Based on implementation at
    from https://github.com/kennethreitz/requests/issues/2554#issuecomment-109341010
    """

    base_url = None

    def request(self, method, url, *args, **kwargs):
        url = urljoin(self.base_url, url )
        if not 'params' in kwargs:
            kwargs['params'] = {}
        kwargs['params']['limit'] = -1
        return super(Based, self).request(method, url, *args, **kwargs)

class BasedSession(Based, requests.Session):
    def __init__(self, base_url=None):
        if base_url:
            self.base_url = base_url
        super(BasedSession, self).__init__()

def generate_id():
    id = str(uuid.uuid4())
    while id in _uuids:
        id = str(uuid.uuid4())
    _uuids.append(id)
    return id

def same_services(service1, service2):
    if service1['service_name'] != service2['service_name']:
        return False
    if service1['protocol'] != service2['protocol']:
        return False
    if service1['port'] != service2['port']:
        return False
    if service1['connection_policy'] != service2['connection_policy']:
        return False
    if 'subprotocols' in service1:
        if not 'subprotocols' in service2:
            return False
        if  len(service1['subprotocols']) != len(service2['subprotocols']):
            return False
        for subprotocols in service1['subprotocols']:
            if not subprotocols in service2['subprotocols']:
                return False
    return True

def print_bastions(bastions, wac, tab):
    wac.write('{}"bastions": {}'.format(tab,  json.dumps(bastions, indent='  ')))

def print_account(account, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "domain_name": "{}",\n'.format(tab, account['domain']))
    if account['device']:
        wac.write('{}  "device_id": "{}",\n'.format(tab, _device_ids[account['device']]))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(account['account_name'])))
    wac.write('{}  "login": {},\n'.format(tab, json.dumps(account['account_login'])))
    wac.write('{}  "has_auto_password_change": {},\n'.format(tab, json.dumps(account['auto_change_password'])))
   
    if not account['application']:
        wac.write('{}  "auto_change_ssh_key": {},\n'.format(tab, json.dumps(account['auto_change_ssh_key'])))

    global  _credential_recovery
    if _credential_recovery and 'credentials' in account:
        for credential in account['credentials']:
            if credential['type'] == 'password':
                wac.write('{}  "password": {},\n'.format(tab, json.dumps(credential['password'])))
            elif credential['type'] == 'ssh_key':
                wac.write('{}  "sss_key": {{\n'.format(tab))
                wac.write('{}    "content": {},\n'.format(tab, json.dumps(credential['private_key'])))
                wac.write('{}    "ssh_title": {}\n'.format(tab, json.dumps(credential['key_type'])))
                wac.write('{}  }},\n'.format(tab))

    wac.write('{}  "description": {}\n'.format(tab, json.dumps(account['description'])))

    wac.write('{}}}'.format(tab))

def print_accounts(wac, tab):
    wac.write('{}"accounts": ['.format(tab))
    comma = "\n"
    for account_name, id in _account_ids.items():
        wac.write(comma)
        print_account(_accounts[account_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_device(device, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(device['device_name'])))
    wac.write('{}  "host": {},\n'.format(tab, json.dumps(device['host'])))
    wac.write('{}  "description": {}\n'.format(tab, json.dumps(device['description'])))
    wac.write('{}}}'.format(tab))

def print_devices(wac, tab):
    wac.write('{}"devices": ['.format(tab))
    comma = "\n"
    for device_name, id in _device_ids.items():
        wac.write(comma)
        print_device(_devices[device_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_jump_server_farm(farm, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {}\n'.format(tab, json.dumps(farm['cluster_name'])))
    wac.write('{}}}'.format(tab))

def print_jump_server_farms(wac, tab):
    wac.write('{}"jump_server_farms": ['.format(tab))
    comma = "\n"
    for farm_name, id in _jump_server_farm_ids.items():
        wac.write(comma)
        print_jump_server_farm(_jump_server_farms[farm_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_jump_server_farm_ref(farm_id, target_id, target_type, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, generate_id()))
    wac.write('{}  "target_id": "{}",\n'.format(tab, target_id))
    wac.write('{}  "jump_server_farm_id": "{}",\n'.format(tab, farm_id))
    wac.write('{}  "target_type": "{}"\n'.format(tab, target_type))
    wac.write('{}}}'.format(tab))

def print_jump_server_farm_refs(wac, tab):
    wac.write('{}"jump_server_farm_refs": ['.format(tab))
    comma = "\n"
    for farm_name, id in _jump_server_farm_ids.items():
        farm = _jump_server_farms[farm_name]
        for target_name in farm['accounts']:
            wac.write(comma)
            print_jump_server_farm_ref(id, _account_target_ids[target_name], "account_targets", tab + "  ", wac)
            comma = ",\n"
        for target_name in farm['account_mappings']:
            wac.write(comma)
            print_jump_server_farm_ref(id, _account_mapping_target_ids[target_name], "account_mapping_targets", tab + "  ", wac)
            comma = ",\n"
        for target_name in farm['interactive_logins']:
            wac.write(comma)
            print_jump_server_farm_ref(id, _interactive_login_target_ids[target_name], "interactive_login_targets", tab + "  ", wac)
            comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_application_interactive_login_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    application_name = target['application']
    wac.write('{}  "application_id": "{}",\n'.format(tab, _application_ids[application_name]))
    wac.write('{}  "application_name": {}\n'.format(tab, json.dumps(application_name)))
    wac.write('{}}}'.format(tab))

def print_application_interactive_login_targets(wac, tab):
    wac.write('{}"application_interactive_login_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _app_interactive_login_target_ids.items():
        wac.write(comma)
        print_application_interactive_login_target(_app_interactive_login_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_application_account_mapping_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    application_name = target['application']
    wac.write('{}  "application_id": "{}",\n'.format(tab, _application_ids[application_name]))
    wac.write('{}  "application_name": {}\n'.format(tab, json.dumps(application_name)))
    wac.write('{}}}'.format(tab))

def print_application_account_mapping_targets(wac, tab):
    wac.write('{}"application_account_mapping_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _app_account_mapping_target_ids.items():
        wac.write(comma)
        print_application_account_mapping_target(_app_account_mapping_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_application_account_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    domain_type = target['domain_type']
    wac.write('{}  "domain_type": "{}",\n'.format(tab, _domain_type_labels[domain_type]))
    account_name = build_account_name(target)
    account_id = _account_ids[account_name] 
    application_name = target['application']
    wac.write('{}  "application_id": "{}",\n'.format(tab, _application_ids[application_name]))
    wac.write('{}  "application_name": {},\n'.format(tab, json.dumps(application_name)))
    wac.write('{}  "account_id": "{}",\n'.format(tab, account_id))
    wac.write('{}  "account_name": {}\n'.format(tab, json.dumps(account_name)))
    wac.write('{}}}'.format(tab))

def print_application_account_targets(wac, tab):
    wac.write('{}"application_account_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _app_account_target_ids.items():
        wac.write(comma)
        print_application_account_target(_app_account_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_application(appplication, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(appplication['application_name'])))
    wac.write('{}  "description": {},\n'.format(tab, json.dumps(appplication['description'])))
    path = appplication['paths'][0]
    wac.write('{}  "path": {},\n'.format(tab, json.dumps(path['program'])))
    wac.write('{}  "startup_directory": {},\n'.format(tab, json.dumps(path['program'])))
    wac.write('{}  "parameters": {},\n'.format(tab, json.dumps(appplication['parameters'])))
    wac.write('{}  "connection_policy_id": "{}",\n'.format(tab, _connection_policy_ids[appplication['connection_policy']]))
    wac.write('{}  "jump_server_farm_id": "{}"\n'.format(tab, _jump_server_farm_ids[appplication['target']]))
    wac.write('{}}}'.format(tab))

def print_applications(wac, tab):
    wac.write('{}"applications": ['.format(tab))
    comma = "\n"
    for application_name, id in _application_ids.items():
        wac.write(comma)
        print_application(_applications[application_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_service(service, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": "{}",\n'.format(tab, service['service_name']))
    wac.write('{}  "protocol": "{}",\n'.format(tab, service['protocol']))
    wac.write('{}  "port": "{}",\n'.format(tab, service['port']))
    comma = ""
    if 'subprotocols' in service:
        wac.write('{}  "subprotocols": ['.format(tab))
        comma = ""
        for subprotocol in service['subprotocols']:
            wac.write('{}\n{}    "{}"'.format(comma, tab, subprotocol))
            comma = ','
        wac.write('\n{}  ],\n'.format(tab))
    policy_name = service['connection_policy']
    wac.write('{}  "connection_policy": "{}"\n'.format(tab, _connection_policy_ids[policy_name]))
    wac.write('{}}}'.format(tab))

def print_services(wac, tab):
    wac.write('{}"services": ['.format(tab))
    comma = "\n"
    for service_name, id in _service_ids.items():
        wac.write(comma)
        print_service(_services[service_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_connection_policy(policy, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": "{}",\n'.format(tab, policy['connection_policy_name']))
    wac.write('{}  "description": {},\n'.format(tab, json.dumps(policy['description'])))
    wac.write('{}  "protocol": "{}",\n'.format(tab, policy['protocol']))
    if 'authentication_methods' in policy:
        wac.write('{}  "authentication_methods": ['.format(tab))
        comma = ""
        for method in policy['authentication_methods']:
            wac.write('{}\n{}    "{}"'.format(comma, tab, method))
            comma = ','
        wac.write('\n{}  ],\n'.format(tab))
    if 'options' in policy:
        wac.write('{}  "options": {},\n'.format(tab, json.dumps(policy['options'], indent="  ")))
    wac.write('{}  "is_default": {}\n'.format(tab, json.dumps(policy.get('is_default', False))))
    wac.write('{}}}'.format(tab))
    
def print_connection_policies(wac, tab):
    wac.write('{}"connection_policies": ['.format(tab))
    comma = "\n"
    for policy_name, id in _connection_policy_ids.items():
        wac.write(comma)
        print_connection_policy(_connection_policies[policy_name], id,  tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_target_ids(target, wac, tab):
    if 'device' in target:
        device_name = target['device']
        service_name = target['service']
        device = _devices[device_name]
        device_id = _device_ids[device_name] 
        wac.write('{}  "device_id": "{}",\n'.format(tab, device_id))
        service_alias = device_name + '_' + service_name
        if service_alias in _services_alias:
            service = _services[service_alias]
        else:
            service = _services[service_name]
        service_id = _service_ids[service_name]
        wac.write('{}  "service_id": "{}",\n'.format(tab, service_id))
    return device, service_name

def print_interactive_login_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    device, service_name = print_target_ids(target, wac, tab)
    wac.write('{}  "device_name": {},\n'.format(tab, json.dumps(device['device_name'])))
    wac.write('{}  "service_name": {}\n'.format(tab, json.dumps(service_name)))
    wac.write('{}}}'.format(tab))

def print_interactive_login_targets(wac, tab):
    wac.write('{}"interactive_login_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _interactive_login_target_ids.items():
        wac.write(comma)
        print_interactive_login_target(_interactive_login_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_account_mapping_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    device, service_name = print_target_ids(target, wac, tab)
    wac.write('{}  "device_name": {},\n'.format(tab, json.dumps(device['device_name'])))
    wac.write('{}  "service_name": {}\n'.format(tab, json.dumps(service_name)))
    wac.write('{}}}'.format(tab))

def print_account_mapping_targets(wac, tab):
    wac.write('{}"account_mapping_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _account_mapping_target_ids.items():
        wac.write(comma)
        print_account_mapping_target(_account_mapping_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_scenario_account_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    if target['device']:
        device_name = target['device']
        device = _devices[device_name]
        device_id = _device_ids[device_name]
        wac.write('{}  "device_id": "{}",\n'.format(tab, device_id))
        wac.write('{}  "device_name": "{}",\n'.format(tab, device['device_name']))
    account_name = target['account'] + '@' + target['domain'] 
    if  target['domain_type'] == 'local':
        account_name = account_name + '@' + target['device']
    account = _accounts[account_name]
    account_id = _account_ids[account_name]
    wac.write('{}  "account_id": "{}",\n'.format(tab, account_id))
    wac.write('{}  "account_name": {},\n'.format(tab, json.dumps(account['account_name'])))
    wac.write('{}  "domain_type": "{}"\n'.format(tab, _domain_type_labels[target['domain_type']]))
    wac.write('{}}}'.format(tab))

def print_scenario_account_targets(wac, tab):
    wac.write('{}"scenario_account_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _scenario_account_target_ids.items():
        wac.write(comma)
        print_scenario_account_target(_scenario_account_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_account_target(target, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    device, service_name = print_target_ids(target, wac, tab)
    domain_type = target['domain_type']
    wac.write('{}  "domain_type": "{}",\n'.format(tab, _domain_type_labels[domain_type]))
    device_name = device['device_name']
    account_name = build_account_name(target)
    account = _accounts[account_name ]
    account_id = _account_ids[account_name] 
    wac.write('{}  "account_id": "{}",\n'.format(tab, account_id))
    wac.write('{}  "account_name": {},\n'.format(tab, json.dumps(account['account_name'])))
    wac.write('{}  "device_name": {},\n'.format(tab, json.dumps(device_name)))
    wac.write('{}  "service_name": {}\n'.format(tab, json.dumps(service_name)))
    wac.write('{}}}'.format(tab))

def print_account_targets(wac, tab):
    wac.write('{}"account_targets": ['.format(tab))
    comma = "\n"
    for target_name, id in _account_target_ids.items():
        wac.write(comma)
        print_account_target(_account_targets[target_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_directory(directory, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(directory['domain_name'])))
    wac.write('{}  "type": {},\n'.format(tab, json.dumps(directory['type'])))
    wac.write('{}  "description": {},\n'.format(tab, json.dumps(directory['description'])))
    wac.write('{}  "domain": {},\n'.format(tab, json.dumps(directory['ldap_domain_name'])))
    wac.write('{}  "default_email_domain": {},\n'.format(tab, json.dumps(directory['default_email_domain'])))
    wac.write('{}  "directory_server_ids": [\n'.format(tab))
    comma = "\n"
    for server in directory['external_ldaps']:
        wac.write(comma)
        wac.write('{}    "{}"'.format(tab, _directory_server_ids[server]))
        comma = "\n,"
    wac.write('{}  ],\n'.format(tab))
    wac.write('{}  "ldap_base": {}\n'.format(tab, json.dumps(directory['ldap_base'])))
    wac.write('{}}}'.format(tab))

def print_directories(wac, tab):
    wac.write('{}"directories": ['.format(tab))
    comma = "\n"
    for dir_name, id in _directory_ids.items():
        wac.write(comma)
        print_directory(_directories[dir_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_directory_server(server, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "bind_method": "{}",\n'.format(tab, "Anonymous" if server['is_anonymous_access'] else "Simple"))
    wac.write('{}  "authentication_name": {},\n'.format(tab, json.dumps(server['authentication_name'])))
    wac.write('{}  "host": {},\n'.format(tab, json.dumps(server['host'])))
    wac.write('{}  "port": {},\n'.format(tab, json.dumps(server['port'])))
    wac.write('{}  "bind_login": {},\n'.format(tab, json.dumps(server['login'])))
    wac.write('{}  "bind_password": {}\n'.format(tab, json.dumps(server['password'])))
    wac.write('{}}}'.format(tab))

def print_directory_servers(wac, tab):
    wac.write('{}"directory_servers": ['.format(tab))
    comma = "\n"
    for server_name, id in _directory_server_ids.items():
        wac.write(comma)
        print_directory_server(_external_auths[server_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_authorization(authorization, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(authorization['authorization_name'])))
    wac.write('{}  "description": {},\n'.format(tab, json.dumps(authorization['description'])))
    wac.write('{}  "target_group_id": "{}",\n'.format(tab, _target_group_ids[authorization['target_group']]))
    wac.write('{}  "user_group_id": "{}",\n'.format(tab, _user_group_ids[authorization['user_group']]))
    wac.write('{}  "is_critical": {},\n'.format(tab, json.dumps(authorization['is_critical'])))
    wac.write('{}  "is_recorded": {},\n'.format(tab, json.dumps(authorization['is_recorded'])))
    wac.write('{}  "authorize_password_retrieval": {}\n'.format(tab, json.dumps(authorization['authorize_password_retrieval'])))
    wac.write('{}}}'.format(tab))

def print_authorizations(wac, tab):
    wac.write('{}"authorizations": ['.format(tab))
    comma = "\n"
    for auth_name, id in _authorization_ids.items():
        wac.write(comma)
        print_authorization(_authorizations[auth_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_user_group(group, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(group['group_name'])))
    wac.write('{}  "description": {},\n'.format(tab, json.dumps(group['description'])))
    if group['group_name'] in _user_group_mappings:
        wac.write('{}  "directories": [\n'.format(tab))
        comma = "\n"
        for mapping in _user_group_mappings[group['group_name']]:
            wac.write(comma)
            wac.write('{}    {{\n'.format(tab))
            wac.write('{}      "directory_id": "{}",\n'.format(tab, _directory_ids[mapping['domain']]))
            wac.write('{}      "directory_group": {}\n'.format(tab, json.dumps(mapping['ldap_group'])))
            wac.write('{}    }}'.format(tab))
            comma = "\n,"
        wac.write('{}  ],\n'.format(tab))
    wac.write('{}  "profile": {}\n'.format(tab, json.dumps(group['profile'])))
    wac.write('{}}}'.format(tab))

def print_user_groups(wac, tab):
    wac.write('{}"user_groups": ['.format(tab))
    comma = "\n"
    for group_name, id in _user_group_ids.items():
        wac.write(comma)
        print_user_group(_user_groups[group_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_target_group(group, id, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, id))
    wac.write('{}  "name": {},\n'.format(tab, json.dumps(group['group_name'])))
    wac.write('{}  "description": {}\n'.format(tab, json.dumps(group['description'])))
    wac.write('{}}}'.format(tab))

def print_target_groups(wac, tab):
    wac.write('{}"target_groups": ['.format(tab))
    comma = "\n"
    for group_name, id in _target_group_ids.items():
        wac.write(comma)
        print_target_group(_target_groups[group_name], id, tab + "  ", wac)
        comma = ",\n"
    wac.write('\n{}]'.format(tab))

def print_target_ref(group_id, target_id, target_type, tab, wac):
    wac.write('{}{{\n'.format(tab))
    wac.write('{}  "id": "{}",\n'.format(tab, generate_id()))
    wac.write('{}  "target_id": "{}",\n'.format(tab, target_id))
    wac.write('{}  "target_group_id": "{}",\n'.format(tab, group_id))
    wac.write('{}  "target_type": "{}"\n'.format(tab, target_type))
    wac.write('{}}}'.format(tab))

def print_target_group_refs(wac, tab):
    wac.write('{}"target_group_refs": ['.format(tab))
    comma = "\n"
    for group_name, id in _target_group_ids.items():
        group = _target_groups[group_name]
        for target in group['session']['accounts']:
            wac.write(comma)
            if target['device']:
                target_name =  target['account'] + '@' + target['domain'] + '@' + target['device'] + ':' + target['service']
                print_target_ref(id, _account_target_ids[target_name], "account_targets", tab + "  ", wac)
            elif target['application']:
                target_name =  target['account'] + '@' + target['domain'] + '@' + target['application']
                print_target_ref(id, _app_account_target_ids[target_name], "application_account_targets", tab + "  ", wac)
            comma = ",\n"
        for target in group['session']['account_mappings']:
            wac.write(comma)
            target_name = target['device'] + ':' + target ['service']
            if target['device']:
                print_target_ref(id, _account_mapping_target_ids[target_name], "account_mapping_targets", tab + "  ", wac)
            elif target['application']:
                    print_target_ref(id, _app_account_mapping_target_ids[target_name], "application_account_mapping_targets", tab + "  ", wac)
            comma = ",\n"
        for target in group['session']['interactive_logins']:
            wac.write(comma)
            target_name = target['device'] + ':' + target ['service']
            if target['device']:
                print_target_ref(id, _interactive_login_target_ids[target_name], "interactive_login_targets", tab + "  ", wac)
            elif target['application']:
                    print_target_ref(id, _app_interactive_login_target_ids[target_name], "application_interactive_login_targets", tab + "  ", wac)
            comma = ",\n"
        for target in group['session']['scenario_accounts']: 
            wac.write(comma)
            target_name = build_account_name(target)
            print_target_ref(id, _scenario_account_target_ids[target_name], "scenario_account_targets", tab + "  ", wac)
            comma = ",\n"
    wac.write('\n{}]'.format(tab))

def build_account_name(target):
    account_name = target['account'] + '@' + target['domain'] 
    if target['domain_type'] == 'local':
        return account_name + '@' + (target['device'] if target['device'] else target['application'])
    else:
        return account_name

def register_account(target):
    account_name = build_account_name(target)
    if not account_name in _account_ids:
        _account_ids[account_name] = generate_id()
    return account_name

def register_device(device_name, service_name):
    if not device_name in _device_ids:
        _device_ids[device_name] = generate_id()
    if service_name:
        service_alias = device_name + '_' + service_name
        if service_alias in _services_alias:
            if not service_alias in _service_ids:
                _service_ids[service_alias] = generate_id()
                service = _services[service_alias]
                policy_name = service['connection_policy']
                if not policy_name in _connection_policy_ids:
                    _connection_policy_ids[policy_name] = generate_id()

        else:
            if not service_name in _service_ids:
                _service_ids[service_name] = generate_id()
                service = _services[service_name]
                policy_name = service['connection_policy']
                if not policy_name in _connection_policy_ids:
                    _connection_policy_ids[policy_name] = generate_id()

def get_accounts(session):
    params = {'passwords': True} if _credential_recovery else {}
    response = session.get('accounts', params=params)

    if response.status_code != 200:
        api_fatal_error(response)
    
    accounts = json.loads(response.content.decode('utf-8'))

    for account in accounts:
        account_name = account['account_name'] + '@' + account['domain']
        if account['device']:
            account_name = account_name + '@' + account['device']
        elif account['application']:
            account_name = account_name + '@' + account['application']
        _accounts[account_name] = account

def get_devices(session):
    response = session.get('devices')

    if response.status_code != 200:
        api_fatal_error(response)
    
    devices = json.loads(response.content.decode('utf-8'))

    for device in devices:
        device_name = device['device_name'] 
        _devices[device_name] = device
        if 'services' in device:
            services = device['services']
            for service in services:
                service_name = service['service_name']
                if service_name in _services:
                    if not same_services(service, _services[service_name]):
                        name = device_name + '_' + service_name
                        service['service_name'] = name
                        _services[name] = service
                        _services_alias[name] = service_name
                else:
                    _services[service_name] = service

def get_applications(session):
    response = session.get('applications')

    if response.status_code != 200:
        api_fatal_error(response)
    
    applications = json.loads(response.content.decode('utf-8'))

    for application in applications:
        application_name = application['application_name'] 
        _applications[application_name] = application
        target = application['target']
        if not target in _jump_server_farms:
            if target in _jump_server_farm_targets:
                application['target'] = _jump_server_farm_targets[target]
            else:
                parts = target.split('@')
                farm = {}
                farm['accounts'] = []
                farm['account_mappings'] = []
                farm['interactive_logins'] = []
                if len(parts) == 1:
                    device, service = parts[0].split(':')
                    farm_name = 'farm_am_' + device
                    farm['account_mappings'] = [target]
                elif len(parts) == 2:
                    device, service = parts[1].split(':')
                    farm_name = 'farm_il_' + device
                    farm['interactive_logins'] = [target]
                else:
                    device, service = parts[2].split(':')
                    farm_name = 'farm_' + device
                    farm['accounts'] = [target]
                farm['cluster_name'] = farm_name
                application['target'] = farm_name
                _jump_server_farms[farm_name] = farm

def get_connection_policies(session):
    response = session.get('connectionpolicies')

    if response.status_code != 200:
        api_fatal_error(response)
    
    connection_policies = json.loads(response.content.decode('utf-8'))
    for policy in connection_policies:
        policy_name = policy['connection_policy_name']
        _connection_policies[policy_name] = policy

def get_external_auths(session):
    response = session.get('externalauths')

    if response.status_code != 200:
        api_fatal_error(response)
    
    external_auths = json.loads(response.content.decode('utf-8'))
    for auth in external_auths:
        auth_name = auth['authentication_name']
        _external_auths[auth_name] = auth

def get_ldap_domains(session):
    response = session.get('ldapdomains')

    if response.status_code != 200:
        api_fatal_error(response)
    
    directories = json.loads(response.content.decode('utf-8'))
    for directory in directories:
        directory_name = directory['domain_name']
        _directories[directory_name] = directory
        _directory_ids[directory_name] = generate_id()
        directory['type'] = "Active Directory"
        for server_name in directory['external_ldaps']:
            server = _external_auths[server_name]
            _directory_server_ids[server_name] = generate_id()
            directory['type'] = "Active Directory" if server['is_active_directory'] else "LDAP"
            directory['ldap_base'] = server['ldap_base']

def get_jump_server_farms(session):
    response = session.get('clusters')

    if response.status_code != 200:
        api_fatal_error(response)
    
    jump_server_farms = json.loads(response.content.decode('utf-8'))
    
    for farm in jump_server_farms:
        farm_name = farm['cluster_name'] 
        _jump_server_farms[farm_name] = farm
        if  'accounts' in farm:
            for target_name in farm['accounts']:
                if not target_name in _account_targets:
                    account_name, domain_name, devnserv = target_name.split('@')
                    device_name, service_name = devnserv.split(':')
                    domain_type = 'global' if _accounts.get(account_name + '@' + domain_name, None) else 'local'
                    _account_targets[target_name] = { 'account' : account_name, 'domain': domain_name,
                         'domain_type' : domain_type , 'device': device_name , 'service': service_name,
                         'application' : None}
                    _account_target_ids[target_name] = generate_id()
                    register_device(device_name, service_name)
        if 'account_mappings' in farm:
            for target_name in farm['account_mappings']:
                if not target_name in _account_mapping_targets:
                    device_name, service_name = target_name.split(':')
                    _account_mapping_targets[target_name] = {'device': device_name , 'service': service_name,
                         'application' : None}
                    _account_mapping_target_ids[target_name] = generate_id()
                    register_device(device_name, service_name)
        if 'interactive_logins' in farm:
            for target_name in farm['interactive_logins']:
                if not target_name in _account_mapping_targets:
                    device_name, service_name = target_name.split(':')
                    interactive_login_targets[target_name] = {'device': device_name , 'service': service_name,
                         'application' : None}
                    interactive_login_target_ids[target_name] = generate_id()
                    register_device(device_name, service_name)

def get_target_groups(session):
    response = session.get('targetgroups')

    if response.status_code != 200:
        api_fatal_error(response)
    
    groups = json.loads(response.content.decode('utf-8'))

    for group in groups:
        group_name = group['group_name'] 
        _target_groups[group_name] = group
        _target_group_ids[group_name] = generate_id()
        for target in group['session']['accounts']:
            if target['device']:
                device_name = target['device']
                service_name = target['service']
                account_name = register_account(target)
                target_name =  target['account'] + '@' + target['domain'] + '@' + target['device'] + ':' + target['service']
                if not target_name in _account_targets:
                    _account_targets[target_name] = target
                    _account_target_ids[target_name] = generate_id()
                register_device(device_name, service_name)
            elif target['application']:
                application_name = target['application']
                if not application_name in _application_ids:
                    _application_ids[application_name] = generate_id()
                    farm_name = _applications[application_name]['target']
                    if not farm_name in _jump_server_farm_ids:
                        _jump_server_farm_ids[farm_name] = generate_id()
                account_name = register_account(target)
                target_name =  target['account'] + '@' + target['domain'] + '@' + target['application']
                if not target_name in _app_account_targets:
                    _app_account_targets[target_name] = target
                    _app_account_target_ids[target_name] = generate_id()
        for target in group['session']['account_mappings']:
            if target['device']:
                device_name = target['device']
                service_name = target['service']
                target_name = device_name + ':' + service_name
                if not target_name in _account_mapping_targets:
                    _account_mapping_targets[target_name] = target
                    _account_mapping_target_ids[target_name] = generate_id()
                register_device(device_name, target['service'])
            elif target['application']:
                application_name = target['application']
                if not application_name in _application_ids:
                    _application_ids[application_name] = generate_id()
                    farm_name = _applications[application_name]['target']
                    if not farm_name in _jump_server_farm_ids:
                        _jump_server_farm_ids[farm_name] = generate_id()
                target_name = application_name
                if not target_name in _app_account_mapping_targets:
                    _app_account_mapping_targets[target_name] = target
                    _app_account_mapping_target_ids[target_name] = generate_id()
        for target in group['session']['interactive_logins']:
            if target['device']:
                device_name = target['device']
                service_name = target['service']
                target_name = device_name + ':' + service_name
                if not target_name in _interactive_login_targets:
                    _interactive_login_targets[target_name] = target
                    _interactive_login_target_ids[target_name] = generate_id()
                register_device(device_name, target['service'])
            elif target['application']:
                application_name = target['application']
                if not application_name in _application_ids:
                    _application_ids[application_name] = generate_id()
                    farm_name = _applications[application_name]['target']
                    if not farm_name in _jump_server_farm_ids:
                        _jump_server_farm_ids[farm_name] = generate_id()
                target_name = application_name
                if not target_name in _app_interactive_login_targets:
                    _app_interactive_login_targets[target_name] = target
                    _app_interactive_login_target_ids[target_name] = generate_id()
        for target in group['session']['scenario_accounts']:
            if target['device']:
                device_name = target['device']
                register_device(device_name, None)
            account_name = register_account(target)
            target_name = account_name
            if not target_name in _scenario_account_targets:
                _scenario_account_targets[target_name] = target
                _scenario_account_target_ids[target_name] = generate_id()

def get_user_groups(session):
    response = session.get('usergroups')

    if response.status_code != 200:
        api_fatal_error(response)
    
    groups = json.loads(response.content.decode('utf-8'))

    for group in groups:
        group_name = group['group_name'] 
        _user_groups[group_name] = group
        _user_group_ids[group_name] = generate_id()
        if not group['profile']:
            group['profile'] = "user"
        
def get_authorizations(session):
    response = session.get('authorizations')

    if response.status_code != 200:
        api_fatal_error(response)
    
    authorizations = json.loads(response.content.decode('utf-8'))

    for authorization in authorizations:
        auth_name = authorization['authorization_name'] 
        _authorizations[auth_name] = authorization
        _authorization_ids[auth_name] = generate_id()

def get_ldap_mappings(session):
    response = session.get('ldapmappings')

    if response.status_code != 200:
        api_fatal_error(response)
    
    mappings = json.loads(response.content.decode('utf-8'))

    for mapping in mappings:
        user_group = mapping['user_group']
        if not user_group in _user_group_mappings:
            _user_group_mappings[user_group] = []
        _user_group_mappings[user_group].append(mapping)

def get_version(session):
    response = session.get('version')

    if response.status_code != 200:
        api_fatal_error(response)

    versions = json.loads(response.content.decode('utf-8'))

    return versions['wab_complete_version']

def get_license(session):
    response = session.get('license')

    if response.status_code != 200:
        api_fatal_error(response)

    info = json.loads(response.content.decode('utf-8'))

    return info['data']

def get_expiration_date(session):
    response = session.get('licenseinfo')

    if response.status_code != 200:
        api_fatal_error(response)

    info = json.loads(response.content.decode('utf-8'))

    return info['expiration_date']

def check_rights(session, credentials):
    response = session.get('preferences')

    if response.status_code != 200:
        api_fatal_error(response)

    preferences = json.loads(response.content.decode('utf-8'))

    rights = preferences['profile_rights']

    requires = {'users', 'user_groups', 'devices', 'target_groups', 'authorizations', 'profiles', 'wab_settings'}

    for right in requires:
        if not rights[right]:
            sys.stderr.write('\033[1;31mError\033[0m: user needs {} right\n'.format(right))
            return False
    
    if credentials:
        if rights['credential_recovery']:
            global _credential_recovery
            _credential_recovery = True
        else:
            sys.stderr.write('\033[1;31mError\033[0m: user needs credential_recovery right\n')
            return False
    return True


def api_fatal_error(response):
    error = json.loads(response.content.decode('utf-8'))
    if error:
        sys.stderr.write("\033[1;31mError: {}:\033[0m {}\n".format(error['error'], error['description']))
    else:
        sys.stderr.write("\033[1;31m{}\033[0m\n".format(str(response)))
    sys.exit(-1)

def emit_json_error(e: json.decoder.JSONDecodeError, doc):
    doc.seek(0)
    lineno = 1
    print(e)
    n = 5
    for line in doc:
        if lineno >= e.lineno - n and lineno <= e.lineno + n :
            sys.stderr.write(line)
        if lineno == e.lineno:
            sys.stderr.write("{}\033[1;31m^\033[0m\n".format(" " * (e.colno - 1)))
        if  lineno == e.lineno + n:
            return
        lineno = lineno + 1

def main():
    parser = argparse.ArgumentParser("Generate a configuration file for WALLIX admin center from a live bastion.")
    parser.add_argument("-c", "--credentials", dest='credentials', action='store_true', required=False,
      help="retrieve account credentials; required credential_recovery rights and 'Credential recovery' REST API option")
    parser.add_argument("-H", "--host", action='store', required=True,  help="bastion host")
    parser.add_argument("-u", "--user", action='store', default=getpass.getuser(), required=False,  help="bastion user's name")
    parser.add_argument("-p", "--password", action='store', required=False,  help="bastion user's password")
    parser.add_argument("-o", "--output", action='store', required=False,  help="wac output file")
    args = parser.parse_args()
 
    if not args.password:
        args.password = getpass.getpass("{0}'s password:".format(args.user))

    if not args.output:
        now = datetime.now()
        args.output = args.host + "-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".wac"

    print("Writing to {0}".format(args.output))

    session = BasedSession('https://{0}/api/'.format(args.host))
    session.auth = (args.user, args.password)
    session.verify = False
    urllib3.disable_warnings()

    if not check_rights(session, credentials=args.credentials):
        sys.exit(-1)

    bastion = {}
    bastion['name'] = args.host.split('.')[0]
    bastion['url'] = args.host
    bastion['version'] = get_version(session)
    bastion['is_online'] = True
    bastion['id'] = generate_id()
    bastion['license_context'] = get_license(session)
    bastion['valid_until'] = get_expiration_date(session)

    get_devices(session)
    get_accounts(session)
    get_connection_policies(session)
    get_external_auths(session)
    get_jump_server_farms(session)
    get_applications(session)
    get_target_groups(session)
    get_user_groups(session)
    get_ldap_domains(session)
    get_ldap_mappings(session)
    get_authorizations(session)

    with TemporaryFile('w+') as wac:
        tab = ''
        wac.write('{}{{\n'.format(tab))

        print_bastions([bastion], wac, tab)
        wac.write(',\n')
        print_account_targets(wac, tab)
        wac.write(',\n')
        print_account_mapping_targets(wac, tab)
        wac.write(',\n')
        print_interactive_login_targets(wac, tab)
        wac.write(',\n')
        print_scenario_account_targets(wac, tab)
        wac.write(',\n')
        print_application_account_targets(wac, tab)
        wac.write(',\n')
        print_application_account_mapping_targets(wac, tab)
        wac.write(',\n')
        print_application_interactive_login_targets(wac, tab)
        wac.write(',\n')
        print_devices(wac, tab)
        wac.write(',\n')
        print_services(wac, tab)
        wac.write(',\n')
        print_accounts(wac, tab)
        wac.write(',\n')
        print_connection_policies(wac, tab)
        wac.write('\n,')
        print_jump_server_farms(wac, tab)
        wac.write('\n,')
        print_jump_server_farm_refs(wac, tab)
        wac.write('\n,')
        print_applications(wac, tab)
        wac.write('\n,')
        print_target_groups(wac, tab)
        wac.write('\n,')
        print_target_group_refs(wac, tab)
        wac.write('\n,')
        print_user_groups(wac, tab)
        wac.write('\n,')
        print_authorizations(wac, tab)
        wac.write('\n,')
        print_directories(wac, tab)
        wac.write('\n,')
        print_directory_servers(wac, tab)

        wac.write('\n}\n')
        wac.seek(0)
        try: 
            data = json.load(wac)
            with open(args.output, 'w') as outfile:
                json.dump(data, outfile, indent=2)
        except json.decoder.JSONDecodeError as e:
            emit_json_error(e, wac)
            sys.exit(1)
        finally:
            wac.close()

if __name__ == "__main__":
    main()
