#!/usr/bin/python
# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: oracle_jms_purge_queue
version_added:
short_description: delete messages in queue jms
description:
     - delete messages in queue jms
options:
  jms_queue:
    description:
      - name of queue or lis of queue
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

requirements:
- wlst

author:
    - christophe.ferreira@cnaf.fr

'''

EXAMPLES = '''

- name: delete message in queue test1
  oracle_jms_purge_queue:
    jms_queue: test1
    domainName: DOMTSTAPI01
  become: true
  become_user: oracle

- name: delete multiple queue
  oracle_jms_purge_queue:
    jms_queue: ['test1', 'test2']
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
            jms_queue = dict(required=True, type='list'),
            domainName  = dict(required=True, type='str'),
            regex       = dict(required=False, type='bool', default=False), 
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains')
        ),
        supports_check_mode=True
    )
    if module.params.get('regex'):
        isregex = 'in'
    else:
        isregex = '=='
    delete_messages_jms_queue = """
import re
import socket
import os
import commands
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
from weblogic.security.internal import *
from weblogic.security.internal.encryption import *

# Variables
list_queue = {jms_queue}
check_mode = {checkmode}
jms_found = 0

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

servers = domainRuntimeService.getServerRuntimes();
if not (len(servers) > 0):
    msg='No server detected in this server'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise

vars_dict= {{}}
vars_dict['changed'] = False
vars_dict['jms_queue'] = {{}}

if (len(servers) > 0):
  for queue_name in list_queue:
    if not queue_name == 'all':
        for server in servers:
            svrName = server.getName()
            jmsRuntime = server.getJMSRuntime();
            jmsServers = jmsRuntime.getJMSServers();
            for jmsServer in jmsServers:
                destinations = jmsServer.getDestinations();
                for destination in destinations:
                    dstName = destination.getName()
                    jms_queue_server_and_name = dstName.split('!')[1]
                    jms_queue_server = jms_queue_server_and_name.split('@')[0]
                    jms_queue_name = jms_queue_server_and_name.split('@')[1]
                    if queue_name {isregex} jms_queue_name :
                        jms_found = 1
                        penCount = destination.getMessagesPendingCount();
                        curCount = destination.getMessagesCurrentCount();
                        sum = penCount + curCount ;
                        jms_current_count = sum
                        jms_paused = destination.isPaused()
                        try: vars_dict['jms_queue'][jms_queue_server]
                        except: vars_dict['jms_queue'][jms_queue_server] = {{}}
                        try: vars_dict['jms_queue'][jms_queue_server]
                        except: vars_dict['jms_queue'][jms_queue_server] = {{}}
                        vars_dict['jms_queue'][jms_queue_server][jms_queue_name] = {{}}
                        vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_current_count_msg'] = jms_current_count
                        #vars_dict['jms_queue'][jms_queue_name]['jms_paused'] = jms_paused
                        if sum > 0:
                            if not check_mode:
                                destination.deleteMessages('');
                                enCount = destination.getMessagesPendingCount();
                                curCount = destination.getMessagesCurrentCount();
                                sum = penCount + curCount ;
                                jms_new_count = sum
                                if sum > 0:
                                    msg='error appear when deleting messages in queue '
                                    msg = msg + dstName
                                    vars_dict = {{}}
                                    vars_dict['changed'] = 'error'
                                    vars_dict['msg'] = msg
                                    print vars_dict
                                    exit()
                                    raise

                                vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_new_count_msg'] = jms_new_count
                                vars_dict['changed'] = True
                            else:
                                if not jms_current_count == 0:
                                    vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_new_count_msg'] = 0
                                    vars_dict['changed'] = True
                                else:
                                    vars_dict['changed'] = False                      
        if jms_found == 0:
          msg = 'jms queue not found '
          vars_dict = {{}}
          vars_dict['changed'] = 'error'
          vars_dict['msg'] = msg
          print vars_dict
          exit()
          raise


    if queue_name == 'all':
        for server in servers:
            jmsRuntime = server.getJMSRuntime();
            jmsServers = jmsRuntime.getJMSServers();
            for jmsServer in jmsServers:
                destinations = jmsServer.getDestinations();
                for destination in destinations:
                    penCount = destination.getMessagesPendingCount();
                    curCount = destination.getMessagesCurrentCount();
                    sum = penCount + curCount ;
                    dstName = destination.getName()
                    jms_queue_server_and_name = dstName.split('!')[1]
                    jms_queue_server = jms_queue_server_and_name.split('@')[0]
                    jms_queue_name = jms_queue_server_and_name.split('@')[1]
                    jms_current_count = sum
                    jms_paused = destination.isPaused()
                    try: vars_dict['jms_queue'][jms_queue_server]
                    except: vars_dict['jms_queue'][jms_queue_server] = {{}}
                    try: vars_dict['jms_queue'][jms_queue_server]
                    except: vars_dict['jms_queue'][jms_queue_server] = {{}}
                    vars_dict['jms_queue'][jms_queue_server][jms_queue_name] = {{}}
                    vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_current_count_msg'] = jms_current_count		    
                    #vars_dict['jms_queue'][jms_queue_name]['jms_paused'] = jms_paused
                    if sum > 0:
                        if not check_mode:
                            destination.deleteMessages('');
                            enCount = destination.getMessagesPendingCount();
                            curCount = destination.getMessagesCurrentCount();
                            sum = penCount + curCount ;
                            jms_new_count = sum
                            if sum > 0:
                                msg='error appear when deleting messages in queue '
                                msg = msg + dstName
                                vars_dict = {{}}
                                vars_dict['changed'] = 'error'
                                vars_dict['msg'] = msg
                                print vars_dict
                                exit()
                                raise

                            vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_new_count_msg'] = jms_new_count
                            vars_dict['changed'] = True
                        else:
                            if not jms_current_count == 0:
                                vars_dict['jms_queue'][jms_queue_server][jms_queue_name]['jms_new_count_msg'] = 0
                                vars_dict['changed'] = True
                    
disconnect()


result = vars_dict
print result
exit
    """

    tmpcreate = tempfile.NamedTemporaryFile()
    try:
          tmpcreate.write(delete_messages_jms_queue.format(domainName=module.params.get('domainName'), isregex=isregex, domainpath=module.params.get('domain_path'), jms_queue=module.params.get('jms_queue'), checkmode=module.check_mode))
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
            module.exit_json(changed=changed, jms_queue=data['jms_queue'])
    except Exception:
        wlst_debug = module.params.get('wlst_path') + ' ' + tmpcreate.name
        msg_error =  commands.getoutput(wlst_debug)
        msg = 'Could not parse json ! error is ' + msg_error
        module.fail_json(msg=msg)

def main():
    run()
if __name__ == "__main__":
    main()

