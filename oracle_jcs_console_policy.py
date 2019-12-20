#!/usr/bin/jython
# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: oracle_jcs_console_policy
version_added: 2.8
short_description: Adding a XACML Role or Policy to a Realm
description:
     - Adding a XACML Role or Policy to a Realm with file or templating lookup
     - This module generate script python used by wlst (jython) in weblogic.
options:
  xacml:
    description:
      - rules for add policy or role with lookkup template or file
    type: str
  realm:
    description:
      - name of the realm.
    type: str
  xacml_path:
    description:
      - path of the xacml rules.
    type: str
  domainName:
    description:
      - domain of the weblogic.
    default: "no"
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

- name: add policy
  oracle_jcs_console_policy:
    xacml: "{{lookup('file', 'JDBCPolicy.xacml')}}"
    xacml_path: "/Authorizers/XACMLAuthorizer"
    realm: myrealm
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
            xacml = dict(required=True, type='str'),
            xacml_path    = dict(required=True, type='str'),
            realm    = dict(required=True, type='str'),
            force    = dict(required=False, type='bool', default=False),
            domainName  = dict(required=True, type='str'),
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains')
        ),
        supports_check_mode=False
    )
    xacml_content = '''
    {xacml}
    '''
    create_policy_py = """
import socket
import os
import commands
import tempfile
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

# Variables
vars_dict= {{}}
vars_dict['changed'] = False
xacml_content = '''{xacml}'''
xacml_path='{xacml_path}'
realm='{realm}'
domainName='{domainName}'
realmPath='/SecurityConfiguration/' + domainName + '/Realms/' + realm
force={force}

try:
    cd (realmPath + xacml_path)
except Exception:
    msg='Error path {xacml_path}'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise

if not force:
    try:
        cmo.addPolicy(xacml_content)
        vars_dict['changed'] = True
    except:
        vars_dict['changed'] = False
else:
    cmo.modifyPolicy(xacml_content)
    vars_dict['changed'] = True


result = vars_dict
print result
exit
    """
    tmpcreate = tempfile.NamedTemporaryFile()
    tmpcreate.write(create_policy_py.format(domainName=module.params.get('domainName'), xacml=module.params.get('xacml'), description=module.params.get('description'), domainpath=module.params.get('domain_path'), xacml_path=module.params.get('xacml_path'), realm=module.params.get('realm'), force=module.params.get('force')))
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
