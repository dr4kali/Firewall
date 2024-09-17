import os

import subprocess

import time



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

    print("Starting OpenVPN...")

    # Use Popen with `nohup` to start OpenVPN in the background and redirect output

    process = subprocess.Popen(

        ["nohup", "sudo", "openvpn", "--config", "/home/dr4kali/Downloads/lab_dr4kali.ovpn"],

        stdout=open("/dev/null", "w"),  # Redirect output to /dev/null to fully detach

        stderr=open("/dev/null", "w"),  # Redirect error to /dev/null to avoid output hanging

        preexec_fn=os.setpgrp  # This fully detaches the process so it doesn’t block the script

    )

    

    # Give OpenVPN time to initialize

    time.sleep(5)

    

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



