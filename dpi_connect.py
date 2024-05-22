import tkinter
from tkinter import messagebox
import requests
import json
import subprocess

def get_credentials_gui():
    window = tkinter.Tk()
    window.title("DPI Connect")

    window.geometry('300x200+30+30')

    username = ""
    password = ""

    def connect():
        username = username_entry.get() + "@pam"
        password = password_entry.get()

        vm_info = get_vmid(username, password)

        if vm_info == False:
            messagebox.showerror("Error", "Could not complete request to backend, see console log")
            return

        # Place FQDN
        fqdn = '#'

        get_session = security_check(username, password)
        get_spice_session_info = get_spice_session(get_session[0], get_session[1], fqdn, vm_info[0], vm_info[1])

        write_file = open("access.vv", "w")

        write_file.write("[virt-viewer]\n"
                         "host=" + get_spice_session_info['title'] + "\n"
                         "password=" + get_spice_session_info['password'] + "\n"
                         "proxy=fqdn"
                         "delete-this-file=1\n"
                         "release-cursor=Ctrl+Alt+R\n"
                         "host-subject=" + get_spice_session_info['host-subject'] + "\n"
                         "ca=" + get_spice_session_info['ca'] + "\n"
                         "type=" + get_spice_session_info['type'] + "\n"
                         "host=" + get_spice_session_info['host'] + "\n"
                         "secure-attention=Ctrl+Alt+Ins\n"
                         "toggle-fullscreen=Shift+F11\n"
                         "tls-port=" + str(get_spice_session_info['tls-port']) + "\n")

        subprocess.Popen('start access.vv', shell=True)

        return

    tkinter.Label(window, text="Username").pack(pady=(30, 0))
    username_entry = tkinter.Entry(window)
    username_entry.pack()
    tkinter.Label(window, text="Password").pack()
    password_entry = tkinter.Entry(window, show="*")
    password_entry.pack()
    tkinter.Button(window, text="Connect", command=connect).pack(side="bottom", pady=(0, 30))
    window.mainloop()

    return

def security_check(username, password):
    login_url = "fqdn"
    login_response = requests.post(login_url, data={'username': username, 'password': password}, verify=False)
    if login_response.status_code == 200:
        print("Authentication Successful\nPOST => FQDN => Response = {0}".format(login_response.status_code))
    json_data = json.loads(login_response.text)
    access_keys = json_data.get('data')
    ticket = access_keys.get('ticket')
    csrf_token = access_keys.get('CSRFPreventionToken')
    credentials_list_proxmox = []
    credentials_list_proxmox.append(ticket)
    credentials_list_proxmox.append(csrf_token)
    return credentials_list_proxmox

def get_spice_session(ticket_cookie, csrf_token, fqdn, pvenode, vmid):
    spice_url = "https://" + fqdn + ":8006/api2/json/nodes/" + pvenode + "/qemu/" + vmid + "/spiceproxy"
    headers = {'CSRFPreventionToken': csrf_token}
    cookies = dict(PVEAuthCookie=ticket_cookie)
    spice_request = requests.post(spice_url, cookies=cookies, headers=headers, verify=False)
    return spice_request.json()['data']

def get_vmid(username, password):
    fqdn = 'FQDN'
    security_info = security_check(username, password)
    cookies = dict(PVEAuthCookie=security_info[0])
    headers = {'CSRFPreventionToken': security_info[1]}
    get_nodes = fqdn + "/cluster/resources"
    request_api = requests.get(get_nodes, cookies=cookies, headers=headers, verify=False)
    request_json = json.loads(request_api.text)
    vmid = ''
    nodeid = ''

    for primary_key in request_json.get('data'):
        if primary_key.get('vmid'):
            print('VM Found in node => {0}'.format(primary_key.get('node')))
            vmid = str(primary_key.get('vmid'))
            nodeid = primary_key.get('node')

    vm_info = []
    vm_info.append(nodeid)
    vm_info.append(vmid)

    return vm_info

if __name__ == '__main__':
    get_credentials_gui()
