import os
import subprocess
import time
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "etc/firewall"))
import config

def loading_animation(duration):
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration

    while time.time() < end_time:
        for frame in spinner:
            sys.stdout.write(f'\rLoading... {frame}')
            sys.stdout.flush()
            time.sleep(0.1)

    sys.stdout.write('\rLoading complete!   \n')

def save_vpn_path(vpn_path):
    # Update the config.py file with the new VPN path
    with open("etc/firewall/config.py", "r") as file:
        lines = file.readlines()
    
    with open("etc/firewall/config.py", "w") as file:
        for line in lines:
            if line.startswith("VPN_CONFIG_PATH ="):
                file.write(f'VPN_CONFIG_PATH = "{vpn_path}"\n')
            else:
                file.write(line)

def get_vpn_path():
    vpn_path = config.VPN_CONFIG_PATH.strip()  # Using the imported config variable
    if vpn_path and os.path.exists(vpn_path):
        print(f"Using VPN file from saved configuration: {vpn_path}")
        return vpn_path
    else:
        while True:
            vpn_path = input("Please provide the correct path to your .ovpn file: ").strip()
            if os.path.exists(vpn_path):
                save_vpn_path(vpn_path)  # Save valid path to config.py
                print(f"VPN path saved to config.py: {vpn_path}")
                return vpn_path
            else:
                print("ERROR: OVPN file not found! Please try again.")

def check_vpn():
    try:
        output = subprocess.check_output("pgrep openvpn", shell=True)
        return bool(output)
    except subprocess.CalledProcessError:
        return False

def start_vpn():
    vpn_path = get_vpn_path()

    print("Starting OpenVPN...")
    # Use Popen with `nohup` to start OpenVPN in the background and redirect output
    process = subprocess.Popen(
        ["nohup", "sudo", "openvpn", "--config", vpn_path],
        stdout=open("/dev/null", "w"),  # Redirect output to /dev/null to fully detach
        stderr=open("/dev/null", "w"),  # Redirect error to /dev/null to avoid output hanging
        preexec_fn=os.setpgrp  # This fully detaches the process so it doesn’t block the script
    )

    # Give OpenVPN time to initialize
    loading_animation(5)

    # Check if OpenVPN started successfully
    if check_vpn():
        print("VPN started successfully.")
    else:
        print("Failed to start VPN.")

def stop_vpn():
    print("Stopping OpenVPN...")
    os.system("sudo pkill -f openvpn")
    loading_animation(5)
    print("VPN stopped.")

def toggle_vpn():
    if check_vpn():
        stop_vpn()
    else:
        start_vpn()

if __name__ == "__main__":
    toggle_vpn()  # Toggle the VPN state
