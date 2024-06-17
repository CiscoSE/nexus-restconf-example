# -*- coding: utf-8 -*-
"""Python example script showing proper use of the Cisco Sample Code header.

Copyright (c) {{2024}} Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import requests, getpass, urllib3, json, base64, struct, math, re, os, argparse

from datetime import datetime

help_msg = ''

argsParse = argparse.ArgumentParser(description=help_msg)
argsParse.add_argument('--switch', '-s',     action='append',     dest='switch_list',      default=None,        required=True,  help="IPs to be inventoried")
argsParse.add_argument('--userName', '-u',   action='store',      dest='username',         default='admin',     required=True,  help="User name for authentication")
argsParse.add_argument('--password', '-p',   action='store',      dest='password',         default=None,        required=False, help="Password for authentication")
argsParse.add_argument('--debugDir',         action='store',      dest='debug_directory',  default='./debug',   required=False, help='Directory debug files are saved into')
argsParse.add_argument('--directory', '-d',  action='store',      dest='report_directory', default='./reports', required=False, help='Directory reports are saved into')
argsParse.add_argument('--verbose', '-v',    action='store_true', dest='debug',            default=False,       required=False, help="Turn on debug output")
argsParse.add_argument('--writeDebug', '-w', action='store_true', dest='write_file',       default=False,       required=False, help="Write JSON File for switches accessed")
args = argsParse.parse_args()

switch_list = args.switch_list
username = args.username

if args.password == None:
    password =      getpass.getpass()
else:
    password =      args.password
debug =             args.debug
write_file =        args.write_file
report_directory =  args.report_directory
debug_directory =   args.debug_directory
report_name =       'Switch-Report.txt'

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

switch_dict = dict()

# Some properties are not available in the 9300v so we use this list to exclude them.
model_exclusions = ["N9K-C9300v"] 

  
class TEXT_COLORS:
    RED =       '\033[91m'
    YELLOW =    '\033[93m'
    GREEN =     '\033[92m'
    DEFAULT =   '\033[0m'

class RESTCONF ():
    switch_name       = '/restconf/data/Cisco-NX-OS-device:System/name'
    switch_model      = '/restconf/data/Cisco-NX-OS-device:System/ch-items/model'
    switch_serial     = '/restconf/data/Cisco-NX-OS-device:System/serial'
    switch_uptime     = '/restconf/data/Cisco-NX-OS-device:System/systemUpTime'
    switch_psus       = '/restconf/data/Cisco-NX-OS-device:System/ch-items/psuslot-items'
    switch_mgmt_mac   = '/restconf/data/Cisco-NX-OS-device:System/mgmt-items/MgmtIf-list=mgmt0/mgmt-items/operRouterMac'
    switch_mgmt_ip    = '/restconf/data/Cisco-NX-OS-device:System/systemTable-items/mgmtIp'
    switch_all        = '/restconf/data/Cisco-NX-OS-device:System' # Only used for new development 

def FILE_TIME ():
    return (datetime.now()).strftime("%Y%m%d-%H%M%S")

def DBG_WR_JSON_TO_FILE(file_name:str,data:str):
    write_data_json = JSON_DUMPS(data)
    if debug == True: print(f"###############################\n{file_name}\n###############################\n\n")
    with open(f"{debug_directory}/{FILE_TIME()}-{file_name}", "w") as open_file:
        open_file.write(write_data_json)

def JSON_DUMPS (unformated_json_data):
    return json.dumps(unformated_json_data, indent=4)

# Depreciated. Only used with RESTCONF openconfig to convert IEEE Float 32 to Float 32.
def CONVERT_PSU_VALUE_TO_DECIMAL(psu_encoded:str):
    if debug == True: print(f"PSU Data To Convert:\t\t\t{psu_encoded}\n")
    byte_string = base64.b64decode(psu_encoded)
    if debug == True: print(f"Byte String To Convert:\t\t\t{byte_string}\n")
    hex_value = byte_string.hex()
    if debug == True: print(f"Hex Value to Convert:\t\t\t{hex_value}\n")
    int_value = int(hex_value, 16)
    if debug == True: print(f"Integer Value to Convert:\t\t{int_value}\n")
    packed_int = struct.pack('>I', int_value)
    if debug == True: print(f"Packed Integer to Convert:\t\t{packed_int}\n")
    end_value = struct.unpack('>f', packed_int)[0]
    if debug == True: print(f"Float Value We Return:\t\t\t{end_value}\n")
    return end_value

def DEBUG_WRITE_TO_SCREEN(title:str, output_message:str) -> None:
    print(f"########## Start {title} ##########\n{output_message}\n########### End {title} ###########\n\n")
    return

def WRITE_STATUS_TO_SCREEN(output_message:str, status:str='INFO') -> None:
    if status == 'INFO': 
        print(f"{TEXT_COLORS.GREEN}[ INFO ]{TEXT_COLORS.DEFAULT}\t{output_message}")
    if status == 'WARN': 
        print(f"{TEXT_COLORS.YELLOW}[ WARN ]{TEXT_COLORS.DEFAULT}\t{output_message}")
    if status == 'FAIL':
        print(f"{TEXT_COLORS.RED}[ FAIL ]{TEXT_COLORS.DEFAULT}\t{output_message}\nEXIT SCRIPT\n")
        exit()
    return

def GET_RESTCONF (system:str, target_path:str):
    headers = {'Accept': 'application/yang.data+json','Content-Type': 'application/yang-data+json'}
    WRITE_STATUS_TO_SCREEN(output_message=f"Getting RESTCONF Data: {system}\t{target_path}")
    target_response = requests.get(f"https://{system}{target_path}", auth=(username, password), headers=headers, verify=False) 
    if debug == True: 
        DEBUG_WRITE_TO_SCREEN(output_message=f"Response Code: {target_response}", title="RESTCONF RESPONSE")
        if target_response.content:
            print(target_response.content)
    if target_response.status_code == "502": WRITE_STATUS_TO_SCREEN(status='WARN',output_message="Possible that RESTCONF is not installed on this switch")
    if not target_response.ok: WRITE_STATUS_TO_SCREEN(output_message=f"Received Status Code {target_response.status_code}", status='FAIL')
    return target_response

def CISCO_PSU_PROCESSING (system:str, report_file:str) -> None:
    WRITE_STATUS_TO_SCREEN(output_message='Getting Power Supply Information')
    switch_psu_cisco_result = GET_RESTCONF(system=system, target_path=RESTCONF.switch_psus)
    if debug == True: DEBUG_WRITE_TO_SCREEN(
        output_message=json.dumps(switch_psu_cisco_result.json(), indent=4),
        title="Power Supply JSON - Cisco RESTCONF"
        )
    if write_file == True: DBG_WR_JSON_TO_FILE(file_name="cisco_psu_report.json", data=switch_psu_cisco_result.json())
    if "PsuSlot-list" in switch_psu_cisco_result.json()['psuslot-items'].keys():
        for psu in switch_psu_cisco_result.json()['psuslot-items']['PsuSlot-list']:
            CISCO_PSU_PROPERTIES(this_psu=psu,report_file=report_file)
    else:
        report_file.write("No power supplies detected - Possible Virtual Instance".center(100))
    return

def CISCO_PSU_PROPERTIES (this_psu:str, report_file:str) -> None:
    return_psu_data = dict()
    WRITE_STATUS_TO_SCREEN(output_message=f"Processing Power Supply {this_psu['id']}")
    if debug == True: DEBUG_WRITE_TO_SCREEN(output_message=json.dumps(this_psu, indent=4),title="Single PSU Report")

    report_file.write("\n     ---------- PSU {0:5}----------\n".format(this_psu.get('id', "Not Found")))
    # Main properties for each Power supply 
    report_file.write("     Power Supply ID: {:<5}\tStatus: {:<10}\tSerial Number: {:<15}Vendor: {:<20}\tModel: {:<15} Revision: {:<6}\tSource: {}\n".format(
            this_psu.get('id',     "Not Found"),
            this_psu.get('operSt', "Not Found"),
            # This is a little harder to read, but it checks for the parent and the child without errors
            this_psu.get('psu-items',{'ser':                "Not Found"}).get('ser',                "Not Found"),
            this_psu.get('psu-items',{'vendor':             "Not Found"}).get('vendor',             "Not Found"),
            this_psu.get('psu-items',{'model':              "Not Found"}).get('model',              "Not Found"),
            this_psu.get('psu-items',{'rev':                "Not Found"}).get('rev',                "Not Found"),
            this_psu.get('psu-items',{'typeCordConnected':  "Not Found"}).get('typeCordConnected',  "Not Found")
            )
        )
    if this_psu.get('psu-items'): 
        these_items = this_psu.get('psu-items')
        report_file.write("     Input Voltage: {0:<10}\tAmps Drawn: {1}\n".format(
            this_psu.get('psu-items',{'vIn': "Not Found"}).get('vIn', "Not Found"),
            this_psu.get('psu-items',{'iIn': "Not Found"}).get('iIn', "Not Found")
            )
        )
    return 

def CISCO_MANAGEMENT_INTERFACE(system:str, report_file:str) -> None:
    WRITE_STATUS_TO_SCREEN(output_message="Searching for Management Interface Properties")
    router_mgmt_mac =  GET_RESTCONF(system=system,target_path=RESTCONF.switch_mgmt_mac).json()
    router_mgmt_ip  =  GET_RESTCONF(system=system,target_path=RESTCONF.switch_mgmt_ip).json()
    report_file.write("\n     ---------- Management Interface Report ----------\n")
    report_file.write("     Management MAC Address: {1:<20}\t Management IP Address: {0:<20}\n".format(
        router_mgmt_ip.get( 'mgmtIp',        'Not Found'),
        router_mgmt_mac.get('operRouterMac', 'Not Found')
    ))
    return

def GET_RESTCONF_MAIN_ATTRIBUTE (system:str, target_path:str, attribute:str) -> str:
    returned_string = GET_RESTCONF(system=system, target_path=target_path)
    if returned_string.json().get(attribute) == None:
        return "Unavailable"
    else:
        return returned_string.json().get(attribute)


def CISCO_SYSTEM_STATE (current_system: str, report_file:str) -> None:
    WRITE_STATUS_TO_SCREEN(output_message=f"Getting System Properties for {current_system}")
    switch_name   = GET_RESTCONF_MAIN_ATTRIBUTE(system=current_system,target_path=RESTCONF.switch_name, attribute='name')
    switch_model  = GET_RESTCONF_MAIN_ATTRIBUTE(system=current_system,target_path=RESTCONF.switch_model, attribute='model') 
    switch_serial = GET_RESTCONF_MAIN_ATTRIBUTE(system=current_system,target_path=RESTCONF.switch_serial, attribute='serial')
    switch_uptime = GET_RESTCONF_MAIN_ATTRIBUTE(system=current_system,target_path=RESTCONF.switch_uptime, attribute='systemUpTime')
    report_file.write(f"Switch Name: {switch_name:<30}\tSwitch Model: {switch_model:<15}\tSwitch Serial: {switch_serial:<25}\tSwitch Uptime: {switch_uptime}\n")
    return

def CHECK_DIR_PATH (dir:str) -> None:
    if not os.path.exists(f"{dir}"):
        WRITE_STATUS_TO_SCREEN(output_message=f"Creating {dir}")
        try:
            os.mkdir(f"{dir}")
        except Exception as err:
            WRITE_STATUS_TO_SCREEN(status='FAIL', output_message=f"Failed to Create Directory: {dir}")
        
        WRITE_STATUS_TO_SCREEN(output_message=f"Created Folder: {dir}")
    else:
        WRITE_STATUS_TO_SCREEN(output_message=f"Existing Folder: {dir} ")
    return

def main () -> None:
    CHECK_DIR_PATH(report_directory)
    if write_file == True: CHECK_DIR_PATH(debug_directory)
    report_file = open(f"{report_directory}/{FILE_TIME()}-{report_name}", "w")
    report_file.write("#"*40 + " Switch Reports" + "#"*40 + "\n")

    for system in switch_list: 
        WRITE_STATUS_TO_SCREEN(output_message=(f"Processing switch {system}"))
        if write_file == True: DBG_WR_JSON_TO_FILE(
            file_name=f"{system}.txt",
            data=GET_RESTCONF(
                system=system,
                target_path=RESTCONF.switch_all).json()
            )
        report_file.write("\n" + '#'*20 + f"Processing Switch {system}" + '#'*20 + "\n")
        CISCO_SYSTEM_STATE(current_system=system, report_file=report_file)
        CISCO_PSU_PROCESSING(system=system, report_file=report_file)
        CISCO_MANAGEMENT_INTERFACE(system=system,report_file=report_file)
        report_file.write("\n")
    return
main()