#!/usr/bin/jython
# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: oracle_jcs_console_user
version_added:
short_description: Create user in weblogic console and attribute role privilege
description:
     - Create and attribute list role privilege.
     - This module generate script python used by wlst (jython) in weblogic.
options:
  state:
    description:
      - add or delete user
    choices: [ present, absent ]
  username:
    description:
      - Name of the user needed to create.
    default: "no"
    type: str
  password:
    description:
      - password of the user needed to create.
    default: "no"
    type: str
  domainName:
    description:
      - domain of the weblogic.
    default: "no"
    type: str
  username:
    description:
      - Name of the user needed to create.
    default: "no"
    type: str
  rolename:
    description:
      - list of role privilege needed for this user.
    default: "no"
    type: list
  description:
    description:
      - Description job of the user.
    default: "no"
    type: str
  password_update:
    description:
      - Force update of the password user.
    default: "false"
    type: bool
  wlst_path:
    description:
      - path of the script utils wlst.
    default: "/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh"
    type: str
  domain_path:
    description:
      - path of the domain in weblogic.
    default: "/u01/data/domains"
    type: str

requirements:
- wlst

author:
    - christophe.ferreira@cnaf.fr

'''

EXAMPLES = '''

- name: create user wls_monitors in weblogic console
  oracle_jcs_console_user:
    state: present
    username: "wls_monitor"
    password: "Mypassword"
    domainName: "DOMTEST01"
    rolename: ['Deployers', 'Monitors']
    description: Supervision
    password_update: false
  become: true
  become_user: oracle

'''


from ansible.module_utils.basic import *


import os
import tempfile
import json
import commands
import types
import ast

def run():
    module = AnsibleModule(
        argument_spec=dict(
            state = dict(required=True, type='str', choices=['absent', 'present']),
            username    = dict(required=True, type='str'),
            password    = dict(required=False, type='str', no_log=True),
            password_update    =dict(required=False, type='bool'),
            rolename    = dict(type='list'),
            description = dict(required=False, type='str'),
            domainName  = dict(required=True, type='str'),
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains')
        ),
        required_if=[
            ["state", "present", ["rolename", "password", "description"] ]
        ],
        supports_check_mode=True
    )
    create_user_py = """
import socket
import os
import commands
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
from weblogic.security.internal import *
from weblogic.security.internal.encryption import *

try:
    cmd_grep_pass = 'grep -Po "(?<=<node-manager-password-encrypted>).*(?=</node-manager-password-encrypted>)" {domainpath}/{domainName}/config/config.xml > /tmp/pass_enc'
    os.system(cmd_grep_pass)
    password_enc = open('/tmp/pass_enc', 'r').read()
    os.remove('/tmp/pass_enc')
    secPath = '{domainpath}/{domainName}/security/'
    encService = SerializedSystemIni.getEncryptionService(secPath)
    coeService = ClearOrEncryptedService(encService)
    adminPassword = coeService.decrypt(str(password_enc))
    adminurl = socket.gethostname().split('.', 1)[0][:-1]
except Exception:
    msg='Error in decryptage of password, check {domainpath}/{domainName}/security'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise

try:
    connect('weblogic',adminPassword,'t3://' + adminurl + '1:7001')
except Exception:
    msg='ERROR Can not connect to interface'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise

try:
    da='/SecurityConfiguration/{domainName}/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator'
    cd(da)
except Exception:
    msg='ERROR the path /SecurityConfiguration/{domainName}/Realms/myrealm/AuthenticationProviders/DefaultAuthenticator not exist'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise

state='{state}'
checkmode={checkmode}
vars_dict= {{}}
vars_dict['changed'] = False
vars_dict['add_member_to'] = 'no'
vars_dict['password_updated'] = False
update_password={password_update}
grouprole={rolename}
grouproleadd = []

if state == 'present':
    if not cmo.userExists('{username}'):
        try:
            if not checkmode:
                cmo.createUser('{username}', '{password}', '{description}')
                for role in grouprole:
                    cmo.addMemberToGroup(role, '{username}')
            vars_dict['changed'] = True
            vars_dict['add_member_to'] = str(grouprole)
            vars_dict['password_updated'] = True
        except Exception:
            msg='ERROR for creating user {username}, the password must be at least 8 characters long, also check if str(grouprole) exist'
            vars_dict = {{}}
            vars_dict['changed'] = 'error'
            vars_dict['msg'] = msg
            print vars_dict
            exit()
            raise

    if cmo.userExists(username) and update_password:
        try:
            if not checkmode:
                cmo.resetUserPassword('{username}', '{password}')
            vars_dict['password_updated'] = True
            vars_dict['changed'] = True
        except Exception:
            msg='ERROR for update password of {username}, the password must be at least 8 characters long '
            vars_dict = {{}}
            vars_dict['changed'] = 'error'
            vars_dict['msg'] = msg
            print vars_dict
            exit()
            raise

    for role in grouprole:
        if not cmo.isMember(role, '{username}', true)==1:
            try:
                if not checkmode:
                    cmo.addMemberToGroup(role, '{username}')
                grouprole.append(grouproleadd)
                vars_dict['add_member_to'] = str(grouproleadd)
                vars_dict['changed'] = True
            except Exception:
                msg='ERROR for add member to role'
                vars_dict = {{}}
                vars_dict['changed'] = 'error'
                vars_dict['msg'] = msg
                print vars_dict
                exit()
                raise

if state == 'absent':
    if cmo.userExists('{username}'):
        if not checkmode:
            try:
                cmo.removeUser('{username}')
            except Exception:
                msg='ERROR for delete user'
                vars_dict = {{}}
                vars_dict['changed'] = 'error'
                vars_dict['msg'] = msg
                print vars_dict
                exit()
                raise
        vars_dict['changed'] = True
    else:
        vars_dict['changed'] = False

result = vars_dict
print result
exit

    """
    tmpcreate = tempfile.NamedTemporaryFile()
    try:
        tmpcreate.write(create_user_py.format(domainName=module.params.get('domainName'), username=module.params.get('username'), rolename=module.params.get('rolename'), password=module.params.get('password'), description=module.params.get('description'), password_update=module.params.get('password_update'), domainpath=module.params.get('domain_path'), state=module.params.get('state'), checkmode=module.check_mode))
    except Exception:
        module.fail_json(msg='error appear in templating script py')
    tmpcreate.seek(0)
    tmp = tmpcreate.read()
    print tmp
    try:
        wls_create = module.params.get('wlst_path') + ' ' + tmpcreate.name+' 2>/dev/null|egrep -i "^ |^--|^{"'
    except Exception:
        module.fail_json(msg='error check path of wlst script')
    try:
        data_json = commands.getoutput(wls_create)
        data_json = ast.literal_eval(data_json)
        data = json.loads(json.dumps(data_json))
        if module.params.get('state') == 'present':
            if data["changed"] == 'error':
                module.fail_json(msg=data["msg"])
            else:
                if data["changed"]:
                    changed=True
                else:
                    changed=False
                if data["password_updated"]:
                    password_changed=True
                else:
                    password_changed=False
            module.exit_json(changed=changed, password_changed=password_changed, add_member_to=data["add_member_to"])
        else:
            if data["changed"]:
                changed=True
            else:
                changed=False
            module.exit_json(changed=changed)
    except Exception:
        wlst_debug = module.params.get('wlst_path') + ' ' + tmpcreate.name
        msg_error =  commands.getoutput(wlst_debug)
        msg = 'Could not parse json ! error is ' + msg_error
        module.fail_json(msg=msg) 

def main():
    run()
if __name__ == "__main__":
    main()
