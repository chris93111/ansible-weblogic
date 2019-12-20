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
  jms_host:
    description:
      - the node number of host jvm
    type: int
    default: 1
  jms_port:
    description:
      - port used by the jvm
    type: int
    default: 9073
  jms_queue_src:
    description:
      - name of queue or lis of queue
    type: str
  jms_queue_dest:
    description:
      - name of queue or lis of queue
    type: str
  jms_server_name_short:
    description:
      - name short of the server
    type: str
  jms_server_name:
    description:
      - name of the server
    type: str
  jms_sysmodule_name:
    description:
      - name of the sysmodule
    type: str
  jms_chunksize:
    description:
      - value of chunksize
    type: str
    default: 3
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

- name: move msg Queue_FluxEnMasse_In_error in Queue_FluxEnMasse_In
  oracle_jms_move_msg:
    domainName: DOMASSJMS01
    jms_host: 1
    jms_port: 9073
    jms_queue_src: Queue_FluxEnMasse_In
    jms_queue_dest: Queue_FluxEnMasse_In_error
    jms_server_name_short: DOMASSJM_server_1
    jms_server_name: JMSServer_DOMASSJM_server_1
    jms_sysmodule_name: SysModule_cluster_ass_jms01
    jms_chunksize: 2
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
            jms_host = dict(required=False, type='int', default='1'),
            jms_port = dict(required=False, type='int', default='9073'),
            jms_queue_src = dict(required=True, type='str'),
            jms_queue_dest = dict(required=True, type='str'),
            jms_server_name = dict(required=True, type='str'),
            jms_server_name_short = dict(required=True, type='str'),
            jms_sysmodule_name = dict(required=True, type='str'),
            jms_chunksize = dict(required=False, type='int', default='3'),
            domainName  = dict(required=True, type='str'),
            wlst_path   = dict(required=False, type='str', default='/u01/app/oracle/middleware/oracle_common/common/bin/wlst.sh'),
            domain_path = dict(required=False, type='str', default='/u01/data/domains')
        ),
        supports_check_mode=True
    )
    move_messages_jms = """
import re
import socket
import os
from java.io import FileInputStream
from weblogic.jms.extensions import JMSMessageInfo
import java.lang
import string
import commands
import weblogic.security.internal.SerializedSystemIni
import weblogic.security.internal.encryption.ClearOrEncryptedService
from weblogic.security.internal import *
from weblogic.security.internal.encryption import *

# Variables
jms_queue_src = '{jms_queue_src}'
jms_queue_dest = '{jms_queue_dest}'
jms_server_name = '{jms_server_name}'
jms_server_name_short = '{jms_server_name_short}'
jms_sysmodule_name = '{jms_sysmodule_name}'
jms_chunksize = '{jms_chunksize}'
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
    exit()
    raise

try:
    connect('weblogic',adminPassword,'t3://' + adminurl + '{jms_host}:{jms_port}')
except Exception:
    msg='ERROR Can not connect to interface'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    exit()
    raise


vars_dict= {{}}
vars_dict['changed'] = False
vars_dict['jms_queue'] = {{}}
vars_dict['jms_queue'][jms_queue_src] = {{}}
vars_dict['jms_queue'][jms_queue_dest] = {{}}

serverRuntime()
try:
    cd('/JMSRuntime/'+jms_server_name_short+'.jms/JMSServers/'+jms_server_name+'/Destinations/'+jms_sysmodule_name +'!'+jms_server_name+'@'+ jms_queue_src)
    JMS_source_queue = cmo
except Exception:
    msg='ERROR could not find path /JMSRuntime/'+jms_server_name_short+'.jms/JMSServers/'+jms_server_name+'/Destinations/'+jms_sysmodule_name +'!'+jms_server_name+'@'+ jms_queue_src
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    disconnect();
    exit()
    raise
try:
    cd('/JMSRuntime/'+jms_server_name_short+'.jms/JMSServers/'+jms_server_name+'/Destinations/'+jms_sysmodule_name +'!'+jms_server_name+'@'+ jms_queue_dest)
    JMS_destination_queue = cmo
except Exception:
    msg='ERROR could not find path /JMSRuntime/'+jms_server_name_short+'.jms/JMSServers/'+jms_server_name+'/Destinations/'+jms_sysmodule_name +'!'+jms_server_name+'@'+ jms_queue_dest
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    disconnect();
    exit()
    raise

try:
    JMS_source_cursor = JMS_source_queue.getMessages('', 0)
    JMS_source_cursor_size = JMS_source_queue.getCursorSize(JMS_source_cursor)
    JMS_dest_size = JMS_destination_queue.getMessagesReceivedCount()
    JMS_dest_size = int(JMS_dest_size)
except Exception:
    msg='could not get message'
    vars_dict = {{}}
    vars_dict['changed'] = 'error'
    vars_dict['msg'] = msg
    print vars_dict
    disconnect();
    exit()
    raise

source_messages = JMS_source_queue.getNext(JMS_source_cursor, int(jms_chunksize))
destination_messages = JMS_dest_size
if source_messages == None:
    vars_dict['jms_queue'][jms_queue_src]['actual_count'] = 0
else:
    vars_dict['jms_queue'][jms_queue_src]['actual_count'] = len(source_messages)
if destination_messages == None:
    vars_dict['jms_queue'][jms_queue_dest]['actual_count'] = 0
else:
    vars_dict['jms_queue'][jms_queue_dest]['actual_count'] = destination_messages

if source_messages != None:
    if not checkmode:
        try:
            for message in source_messages:
                msgwithbody = JMSMessageInfo(message)
                message_id = msgwithbody.getMessage().getJMSMessageID()
                JMS_source_queue.moveMessages("JMSMessageID='" + message_id + "'", JMS_destination_queue.getDestinationInfo())
                vars_dict['changed'] = True
        except Exception:
            msg='Oups error for move messages'
            vars_dict = {{}}
            vars_dict['changed'] = 'error'
            vars_dict['msg'] = msg
            print vars_dict
            disconnect();
            exit()
            raise
        new_source_messages = JMS_source_queue.getNext(JMS_source_cursor, int(jms_chunksize))
        new_destination_messages = int(JMS_destination_queue.getMessagesReceivedCount())
        if new_source_messages == None:
            vars_dict['jms_queue'][jms_queue_src]['new_count'] = 0
        else:
            vars_dict['jms_queue'][jms_queue_src]['new_count'] = len(new_source_messages)
        vars_dict['jms_queue'][jms_queue_dest]['new_count'] = new_destination_messages
else:
    vars_dict['jms_queue'][jms_queue_src]['actual_count'] = 0

result = vars_dict
print result
disconnect();
exit();
    """

    tmpcreate = tempfile.NamedTemporaryFile()
    try:
          tmpcreate.write(move_messages_jms.format(domainName=module.params.get('domainName'), domainpath=module.params.get('domain_path'), jms_queue_src=module.params.get('jms_queue_src'), jms_queue_dest=module.params.get('jms_queue_dest'), jms_server_name_short=module.params.get('jms_server_name_short'), jms_server_name=module.params.get('jms_server_name'), jms_sysmodule_name=module.params.get('jms_sysmodule_name'), jms_chunksize=module.params.get('jms_chunksize'),
jms_host=module.params.get('jms_host'), jms_port=module.params.get('jms_port'), checkmode=module.check_mode))
    except Exception:
        module.fail_json(msg='error appear in templating script py')
    tmpcreate.seek(0)
    tmp = tmpcreate.read()
    try:
        wls_create = module.params.get('wlst_path') + ' ' + tmpcreate.name+' 2>/dev/null|egrep -i "^{"'
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

