#!/usr/bin/jython
# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: oracle_jcs_console_group
version_added: 2.8
short_description: Create group in weblogic console
description:
     - Create group in welblogic
     - This module generate script python used by wlst (jython) in weblogic.
options:
  state:
    description:
      - add or delete group
    choices: [ present, absent ]
  group:
    description:
      - Name of the user needed to create.
    type: str
  description:
    description:
      - Description job of the group.
    type: str
  domainName:
    description:
      - domain of the weblogic.
    type: str
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

- name: create group wls_monitors in weblogic console
  oracle_jcs_console_group:
    state: present
    group: "wls_monitor"
    description: monitor
    domainName: "DOMTEST01"
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
            group    = dict(required=True, type='str'),
            description    = dict(required=False, type='str', default=''),
            domainName  = dict(required=True, type='str'),
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains')
        ),
        supports_check_mode=True
    )
    create_group_py = """
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

# Variables
vars_dict= {{}}
vars_dict['changed'] = False
state='{state}'
checkmode={checkmode}

if state == 'present':
    if not cmo.groupExists('{groupname}'):
        try:
            if not checkmode:
                cmo.createGroup('{groupname}', '{description}')
            vars_dict['changed'] = True
        except Exception:
            msg='ERROR for creating group {groupname}'
            vars_dict = {{}}
            vars_dict['changed'] = 'error'
            vars_dict['msg'] = msg
            print vars_dict
            exit()
            raise

if state == 'absent':
    if cmo.groupExists('{groupname}'):
        if not checkmode:
            try:
                cmo.removeGroup('{groupname}')
            except Exception:
                msg='ERROR for remove group {groupname}'
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
        tmpcreate.write(create_group_py.format(domainName=module.params.get('domainName'), groupname=module.params.get('group'), description=module.params.get('description'), domainpath=module.params.get('domain_path'), state=module.params.get('state'), checkmode=module.check_mode))
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
        if data["changed"] == 'error':
            module.fail_json(msg=data["msg"])
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
