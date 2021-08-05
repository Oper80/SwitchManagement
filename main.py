import sys
from netmiko import ConnectHandler
import PySimpleGUI as sg
from datetime import datetime
import time
import multiprocessing
import re
import os
from itertools import product

start_time = time.time()


def find_MAC(connection_data, *args):
    # Enter MAC or part of MAC xxxx.xxxx.xxxx
    mac = args[0]
    mac_layout = [
        [sg.Output(size=(88, 20))],
        [sg.Cancel(button_text='Done')]
    ]
    mac_window = sg.Window('Search MAC address', mac_layout, finalize=True)
    if mac == "":
        print("Enter valid MAC address")
        return
    ip_address = connection_data[0]
    device_type = connection_data[1]
    username = connection_data[2]
    password = connection_data[3]
    ip_check = re.findall(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        ip_address)
    if ip_check == []:
        print(f'Invalid IP -  {str(ip_address)}')
        return ['fail', ip_address]

    device = {
        'device_type': device_type,  # device type for HP 'hp_procurve'
        'ip': ip_address.strip(),
        'username': username,
        'password': password,
        'port': 22}
    try:
        cli_response = net_connect = ConnectHandler(**device)
        cli_response = net_connect.send_command(f'sh mac add | in {mac}')
        hostname = net_connect.send_command(f'sh run | in hostname')
        hostname = hostname.split()[1]
        net_connect.disconnect()
    except:
        print(f'\n{str(ip_address)}  Cannot connect to this device.')
        print(f'user: {username} password {password}')
        return ['fail', ip_address]

    # print(f'\n\n------switch {ip_address}------')
    # print(f'{cli_response}')
    # print("--------- End ---------")

    while True:  # The Event Loop
        mac_window.enable()
        mac_window.set_title(hostname)
        print(f'\n\n------switch {ip_address}------')
        print(f'{cli_response}')
        print("--------- End ---------")
        mac_event, mac_values = mac_window.read()

        if mac_event in (None, 'Exit', 'Done'):
            mac_window.close()
            return ['done', ip_address, hostname]


def set_vlans(connection_data, *args):
    vlan_layout = [
        [sg.Output(size=(88, 20))],
        [sg.Cancel(button_text='Done')]
    ]
    vlan_window = sg.Window('Set vlans', vlan_layout, finalize=True)
    ip_address = connection_data[0]
    device_type = connection_data[1]
    username = connection_data[2]
    password = connection_data[3]

    ip_check = re.findall(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        ip_address)
    if ip_check == []:
        print(f'Invalid IP -  {str(ip_address)}')
        return ['fail', ip_address]

    device = {
        'device_type': device_type,  # device type for HP 'hp_procurve'
        'ip': ip_address.strip(),
        'username': username,
        'password': password,
        'port': 22}
    try:
        f = open('vlans.txt')
        f_lines = f.read().splitlines()
        vlan_num = list(map(lambda x: x.split(",")[0], f_lines))
        vlan_name = list(map(lambda x: x.split(",")[1], f_lines))
        new_vlans = dict(zip(vlan_num, vlan_name))
        f.close()
    except:
        sys.exit("Couldn't open or read file vlans.txt")
    config_commands = []
    try:
        cli_response = net_connect = ConnectHandler(**device)
        cli_response = net_connect.send_command(f'sh vlan | in active')
        hostname = net_connect.send_command(f'sh run | in hostname')
        hostname = hostname.split()[1]
        vlans = list(map(lambda x: x.split()[0:2], list(cli_response.splitlines())))

        # delete unused vlans
        for vlan in vlans:
            if (new_vlans.get(vlan[0], "null") == "null" and vlan[0] != '1') or (
                    vlan[0] == '3' and ip_address != '192.168.11.10'):  # exept vlan 3 on cisco in Rack1
                config_commands.append('no vlan ' + vlan[0])

        # rename or create vlans
        for k, v in new_vlans.items():
            if k != '3' or (k == '3' and ip_address == '192.168.11.10'):
                config_commands.extend(('vlan ' + k, 'name ' + v, 'exit'))

    except:
        print(f'\n{str(ip_address)}  Cannot connect to this device.')
        print(f'user: {username} password {password}')
        return ['fail', ip_address]

    try:
        net_connect.send_config_set(config_commands)
        net_connect.send_command_expect('write memory')
        cli_response = net_connect.send_command(f'sh vlan | in active')
        net_connect.disconnect()
    except:
        print(f'\n{str(ip_address)}  Cannot execute commands on this device.')
        print(f'user: {username} password {password}')
        return ['fail', ip_address]

    while True:  # The Event Loop
        vlan_window.enable()
        vlan_window.set_title(hostname)
        print(f'\n\n------switch {ip_address}------')
        print(f'{cli_response}')
        print("--------- End ---------")
        mac_event, mac_values = vlan_window.read()

        if mac_event in (None, 'Exit', 'Done'):
            vlan_window.close()
            return ['done', ip_address, hostname]


def copy_configs(connection_data, *args):
    ip_address = connection_data[0]
    device_type = connection_data[1]
    username = connection_data[2]
    password = connection_data[3]
    today = str(datetime.now().strftime('%Y-%m-%d-%H-%M'))
    tftp = args[0]
    ip_check = re.findall(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        ip_address)
    if ip_check == []:
        print(f'Invalid IP -  {str(ip_address)}')
        return ['fail', ip_address]

    device = {
        'device_type': device_type,  # device type for HP 'hp_procurve'
        'ip': ip_address.strip(),
        'username': username,
        'password': password,
        'port': 22}
    try:
        cli_response = net_connect = ConnectHandler(**device)
        hostname = net_connect.send_command(f'sh run | in hostname')
        hostname = hostname.split()[1]
        filename = (today + "_" + hostname + ".txt")
        output = net_connect.send_command_timing("copy running-config tftp")
        if 'Source filename' in output:
            output += net_connect.send_command_timing('\n')
        if 'remote host' in output:
            output += net_connect.send_command_timing(tftp)
        if 'Destination filename' in output:
            output += net_connect.send_command_timing(filename)
        net_connect.disconnect()
    except:
        print(f'\n{str(ip_address)}  Cannot connect to this device.')
        print(f'user: {username} password {password}')
        return ['fail', ip_address]

    return ['done', ip_address, hostname]


if __name__ == '__main__':

    # Choose function to use
    global_username = "cisco"
    global_password = "cisco"
    func_list = [set_vlans, find_MAC, copy_configs]
    func_names = {'> Set vlans from file': 0, '> Find MAC': 1, '> Copy configs': 2}
    files_list = ["D:/PythonProjects/SwitchManagement/vlans.txt",
                  "D:/PythonProjects/SwitchManagement/ip.txt"]
    files_names = {'Vlans list': 0, 'Switches list': 1}
    tftp_path = '10.0.50.201'
    filename = ""
    comments = ['Update vlans on switches acording to file vlans.txt in root directory',
                'Find MAC address on all switches. \nThis command will open window for each switch with search results',
                'Copy config from each switch to TFTP directory. \nTFTP server must be started']
    func = None
    # Variable to send *args into functions
    args = []
    # sg.theme('DarkBlue')
    left_col = sg.Column([
        [sg.Text('Choose function', font='Any 20', size=(47, 1))],
        [sg.Listbox(values=list(func_names.keys()), key='-LIST-', size=(30, 6), font='Any 12 bold',
                    no_scrollbar=True, enable_events=True, background_color='floral white')],
        [sg.Text("Choose function and press Submit.", key='-comments-', size=(40, 3), font='Any 11 bold', text_color='bisque')],
        [sg.Submit(key='Submit', font='Any 12 bold', disabled=True),
         sg.Button(button_text="Open TFTP folder", key='-TFTP-')],
    ], element_justification='l', expand_x=True, expand_y=True)
    right_col = sg.Column([
        [sg.Text('Choose file to edit', font='Any 20', size=(20, 1))],
        [sg.Listbox(values=list(files_names.keys()), size=(30, 6), key='-FILES-', font='Any 12 bold',
                    no_scrollbar=True, enable_events=True, background_color='floral white')],
        [sg.Text("Edit Vlans list file to create new or delete old vlan \n"
                 "Edit Switches list file to select switches to connect\n", font='Any 11 bold', text_color='bisque')],
        [sg.Button(button_text="Open", disabled=True, key='-Open-', font='Any 10 bold')],
    ])
    layout = [[sg.Pane([left_col, right_col], orientation='h')],
              [sg.Output(size=(160, 30), background_color='gainsboro')],
              [sg.Cancel(key='Cancel')]
              ]
    window = sg.Window('Network management', layout)
    while True:  # The Event Loop
        event, values = window.read()
        # print(event, values) #debug
        if event == '-FILES-':
            filename = files_list[files_names[values['-FILES-'][0]]]
            window['-Open-'].update(disabled=False)
        if event == '-Open-':
            os.system("notepad.exe " + '"' + filename + '"')
        if event in (None, 'Exit', 'Cancel'):
            break
        if event == '-TFTP-':
            os.system("start D:/TFTP")
        if event == '-LIST-':
            func = func_list[func_names[values['-LIST-'][0]]]
            window['Submit'].update(disabled=False)
            window['-comments-'].update(comments[func_names[values['-LIST-'][0]]])
        if event == 'Submit':
            print("Starting...")
            # Enter valid username and password. Note password is blanked out using the getpass library


            try:
                print("Reading ip addresses from file...")
                f = open('ip.txt')
                connection_data = []
                filelines = f.read().splitlines()
                for line in filelines:
                    if line == "": continue
                    if line[0] == "#": continue
                    conn_data = line.split(',')
                    ipaddr = conn_data[0].strip()
                    username = global_username
                    password = global_password
                    device_type = 'cisco_ios'
                    if len(conn_data) > 1 and conn_data[1].strip() != "": device_type = conn_data[1].strip()
                    if len(conn_data) > 2 and conn_data[2].strip() != "": username = conn_data[2].strip()
                    if len(conn_data) > 3 and conn_data[3].strip() != "": password = conn_data[3].strip()
                    connection_data.append((ipaddr, device_type, username, password))
                f.close()
                print("Done")
            except:
                sys.exit("Couldn't open or read file ip.txt")
            print("Starting connections...")
            if values['-LIST-'][0] == '> Find MAC':
                layout_mac = [
                    [sg.Text('Enter MAC or part of MAC in xxxx.xxxx.xxxx format'),
                     sg.InputText()],
                    [sg.Submit(), sg.Cancel()]
                ]
                window_mac = sg.Window('Enter MAC address', layout_mac)
                while True:  # The Event Loop
                    event_1, values_1 = window_mac.read()
                    if event_1 in (None, 'Exit', 'Cancel'):
                        break
                    if event_1 == 'Submit':
                        args.append(values_1[0])
                        window_mac.close()
                        break
            if values['-LIST-'][0] == '> Set vlans from file':
                args.append('none')

            if values['-LIST-'][0] == '> Copy configs':
                args.append(tftp_path)
            multiprocessing.set_start_method("spawn")
            with multiprocessing.Pool(maxtasksperchild=10) as process_pool:
                switches_with_issues = process_pool.starmap(func, product(connection_data, args), 1)
                process_pool.close()
                process_pool.join()

            print("\n")
            print("#These switches failed to execute#\n")

            for item in switches_with_issues:
                if item != None and item[0] == 'fail':
                    print(item[1])
            print("--------- End ---------\n")
            print("#These switches executed successfully#\n")

            for item in switches_with_issues:
                if item != None and item[0] == 'done':
                    print(f'{item[1]}  ---  {item[2]}')
            print("--------- End ---------\n")
            # Completing the script and print running time
            print("#This script has now completed#\n")
            print("--- %s seconds ---" % (time.time() - start_time))
            window['Submit'].update(visible=False)
            window['Cancel'].update(text="Exit")
