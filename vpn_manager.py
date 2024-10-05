import os
import subprocess
import time
import sys
import time

def loading_animation(duration):
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration

    while time.time() < end_time:
        for frame in spinner:
            sys.stdout.write(f'\rLoading... {frame}')
            sys.stdout.flush()
            time.sleep(0.1)  # Adjust the speed of the spinner here

    sys.stdout.write('\rLoading complete!   \n')  # Clear the line after loading


# File to store the VPN config path
VPN_CONFIG_FILE = "vpn_config.txt"

# Function to save the VPN path
def save_vpn_path(vpn_path):
    with open(VPN_CONFIG_FILE, "w") as config_file:
        config_file.write(vpn_path)

# Function to load the VPN path
def load_vpn_path():
    if os.path.exists(VPN_CONFIG_FILE):
        with open(VPN_CONFIG_FILE, "r") as config_file:
            return config_file.read().strip()
    return None

# Function to get the VPN path from the user
def get_vpn_path():
    vpn_path = load_vpn_path()
    if vpn_path and os.path.exists(vpn_path):
        print(f"Using VPN file from saved configuration: {vpn_path}")
        return vpn_path
    else:
        vpn_path = input("Please provide the correct path to your .ovpn file: ").strip()
        if os.path.exists(vpn_path):
            save_vpn_path(vpn_path)
            return vpn_path
        else:
            print("ERROR: OVPN file not found!")
            return get_vpn_path()

# Check if OpenVPN is running
def check_vpn():
    try:
        output = subprocess.check_output("pgrep openvpn", shell=True)
        if output:
            return True
    except subprocess.CalledProcessError:
        return False

# Start OpenVPN
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

# Stop OpenVPN
def stop_vpn():
    print("Stopping OpenVPN...")
    os.system("sudo pkill -f openvpn")
    print("VPN stopped.")

# Toggle VPN state
def toggle_vpn():
    if check_vpn():
        stop_vpn()
    else:
        start_vpn()

# Main function that runs the toggle_vpn without blocking the interactive shell
if __name__ == "__main__":
    toggle_vpn()
