#!/usr/bin/python
# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: oracle_jcs_console_bootargs
version_added:
short_description: add or delete parameter in console weblogic
description:
     - add boot paramters or delete with pattern to console weblogic
options:
  state:
    description:
      - add or delete parameters
    choices: [ present, absent ]
  regexp:
    description:
      - the regex for delete in console
    type: str
  domainName:
    description:
      - the domain name of jcs
  wlst_path:
    description:
      - path of wlst script
    default: /u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh
  domain_path:
    description:
      - path of home domain
    default: /u01/data/domains
  arguments:
    descripton:
      - args needed to add
  servers:
    description:
      - list of servers to add or delete boot args

requirements:
- wlst

author:
    - christophe.ferreira@cnaf.fr

'''

EXAMPLES = '''

- name: delete xmx and xms in boot args console
  oracle_jcs_console_rm_bootargs:
    state: absent
    regexp: '-Xm([sx])([0-9]+)m'
    domainName: DOMTSTAPI01
  become: true
  become_user: oracle

- name: add xmx in boot args console
  oracle_jcs_console_rm_bootargs:
    state: present
    arguments: '-Xms256m -Xmx2048m'
    domainName: DOMTSTAPI01
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
            arguments = dict(required=False, type='str'),
            regexp = dict(required=False, type='str'),
            domainName  = dict(required=True, type='str'),
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains'),
            servers = dict(required=False, type='list', default=['all']),
            servers_regexp = dict(required=False, type='str', default='')
        ),
        required_if=[
            ["state", "absent", ["regexp"] ],
            ["state", "present", ["arguments"] ]
        ],
        supports_check_mode=True
    )

    delete_args_py = """
import re
import socket
import os
import commands
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
from weblogic.security.internal import *
from weblogic.security.internal.encryption import *

# Variables
patternStr = "{regexp}"
checkmode = {checkmode}


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
    raise

try:
    connect('weblogic',adminPassword,'t3://' + adminurl + '1:7001')
except Exception:
    msg='ERROR Can not connect to interface'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    raise

domainConfig()
edit()
startEdit()
cd('/')
servers_list = {servers}
servers_regexp = '{servers_regexp}'

if 'all' in servers_list:
    srvList = cmo.getServers()
else:
    srvList = servers_list

vars_dict= {{}}
vars_dict['changed'] = False
vars_dict['servers'] = {{}}

for curSrv in srvList:
  if 'all' in servers_list:
      if not servers_regexp == '':
          servername = curSrv.getName()
          if servers_regexp in servername:
              curSrvName = curSrv.getName()
          else:
              continue
      else:
          curSrvName = curSrv.getName()
  else:
      curSrvName = curSrv 
  cd('/Servers/'+curSrvName+'/ServerStart/'+curSrvName)
  curStr = cmo.getArguments()
  vars_dict['servers'][curSrvName] = {{}}
  vars_dict['servers'][curSrvName]['old argument'] = curStr
  if curStr != None :
    if re.search(r''+patternStr,curStr):
      curStr = re.sub(r''+patternStr, "", curStr)
      if not checkmode:
          cmo.setArguments(curStr)
      vars_dict['changed'] = True
      vars_dict['servers'][curSrvName]['new argument'] = curStr
save()
activate()


result = vars_dict
print result
exit
    """
    add_args_py = """
import re
import socket
import os
import commands
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
from weblogic.security.internal import *
from weblogic.security.internal.encryption import *

# Variables
addargs = "{arguments}"
checkmode = {checkmode}

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
    raise

try:
    connect('weblogic',adminPassword,'t3://' + adminurl + '1:7001')
except Exception:
    msg='ERROR Can not connect to interface'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    raise

domainConfig()
edit()
startEdit()
cd('/')
servers_list = {servers}
servers_regexp = '{servers_regexp}'
if 'all' in servers_list:
    srvList = cmo.getServers()
else:
    srvList = servers_list

vars_dict= {{}}
vars_dict['changed'] = False
vars_dict['servers'] = {{}}

for curSrv in srvList:
  if 'all' in servers_list:
      if not servers_regexp == '':
          servername = curSrv.getName()
          if servers_regexp in servername:
              curSrvName = curSrv.getName()
          else:
              continue
      else:
          curSrvName = curSrv.getName()
  else:
      curSrvName = curSrv 
  cd('/Servers/'+curSrvName+'/ServerStart/'+curSrvName)
  curStr = cmo.getArguments()
  vars_dict['servers'][curSrvName] = {{}}
  vars_dict['servers'][curSrvName]['old argument'] = curStr
  if curStr == None :
      curStr = ''
  if not re.search(r''+addargs,curStr):
      curStr = addargs + ' ' + curStr
      if not checkmode:
          cmo.setArguments(curStr)
      vars_dict['changed'] = True
      vars_dict['servers'][curSrvName]['new argument'] = curStr
save()
activate()


result = vars_dict
print result
exit
    """
    tmpcreate = tempfile.NamedTemporaryFile()
    try:
        if module.params.get('state') == 'absent':        
          tmpcreate.write(delete_args_py.format(domainName=module.params.get('domainName'), domainpath=module.params.get('domain_path'), regexp=module.params.get('regexp'), servers=module.params.get('servers'), servers_regexp=module.params.get('servers_regexp'), checkmode=module.check_mode))
        if module.params.get('state') == 'present':
          tmpcreate.write(add_args_py.format(domainName=module.params.get('domainName'), domainpath=module.params.get('domain_path'), arguments=module.params.get('arguments'), servers=module.params.get('servers'), servers_regexp=module.params.get('servers_regexp'), checkmode=module.check_mode))  
    except Exception:
        module.fail_json(msg='error appear in templating script py')
    tmpcreate.seek(0)
    tmp = tmpcreate.read()
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
            module.exit_json(changed=changed, servers=data['servers'])
    except Exception:
        wlst_debug = module.params.get('wlst_path') + ' ' + tmpcreate.name
        msg_error =  commands.getoutput(wlst_debug)
        msg = 'Could not parse json ! error is ' + msg_error
        module.fail_json(msg=msg)

def main():
    run()
if __name__ == "__main__":
    main()

