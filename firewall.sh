#!/bin/bash
echo "  █████▒ ██▓ ██▀███  ▓█████  █     █░ ▄▄▄       ██▓     ██▓    ";
echo "▓██   ▒ ▓██▒▓██ ▒ ██▒▓█   ▀ ▓█░ █ ░█░▒████▄    ▓██▒    ▓██▒    ";
echo "▒████ ░ ▒██▒▓██ ░▄█ ▒▒███   ▒█░ █ ░█ ▒██  ▀█▄  ▒██░    ▒██░    ";
echo "░▓█▒  ░ ░██░▒██▀▀█▄  ▒▓█  ▄ ░█░ █ ░█ ░██▄▄▄▄██ ▒██░    ▒██░    ";
echo "░▒█░    ░██░░██▓ ▒██▒░▒████▒░░██▒██▓  ▓█   ▓██▒░██████▒░██████▒";
echo " ▒ ░    ░▓  ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░";
echo " ░       ▒ ░  ░▒ ░ ▒░ ░ ░  ░  ▒ ░ ░    ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░";
echo " ░ ░     ▒ ░  ░░   ░    ░     ░   ░    ░   ▒     ░ ░     ░ ░   ";
echo "         ░     ░        ░  ░    ░          ░  ░    ░  ░    ░  ░";
echo "                                                               ";



# Function to manage the firewall and NFQUEUE setup
manage_firewall() {
    # Set up iptables rules for NFQUEUE
    sudo sysctl -qw net.ipv4.ip_forward=1 
    python3 threat_intelligence.py & 

    # Get the active interface dynamically
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}')
    sudo iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE

    sudo iptables -I INPUT -j NFQUEUE --queue-num 0
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
    sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

    # Start the Python firewall script in the background
    sudo python3 firewall.py >> var/firewall/output.log 2>&1 &  # Run the firewall in the background
}

# Function to stop the firewall
stop_firewall() {
    sudo sysctl -qw net.ipv4.ip_forward=0
    echo "Stopping the firewall..."
    sudo pkill -f firewall.py
    sudo pkill -f threat_intelligence.py
    sudo iptables -F  # Flush all iptables rules
    echo "Firewall stopped."
}

# Function to handle the firewall operations
firewall() {
    manage_firewall

    while true; do
        echo "Select an Operation"
        echo "1. Add or Remove Firewall Rules"
        echo "2. Stop the Firewall"
        echo "3. View Logs in Real-Time"
        echo "4. Toggle VPN Service"
        echo "5. Exit"
        read -p "Enter the number: " op

        case $op in
            1)
                # Open the firewall rules file in vim to add or remove rules
                sudo vim var/firewall/rules
                if find var/firewall/rules -mmin -0.083 | grep -q "var/firewall/rules" ; then
                    stop_firewall
                    manage_firewall
                fi
                ;;
            2)
                # Stop the firewall by killing the Python process and flushing iptables
                stop_firewall
                break
                ;;
            3)
                # Display the logs in real-time
                echo "Displaying logs in real-time."
                sudo python gui_logger.py
                ;;
            4)
                # Stop firewall and flush iptables before starting VPN
                sudo iptables -F
                stop_firewall

                # Start VPN via the Python script
                sudo python3 vpn_manager.py

                # Restart the firewall
                manage_firewall
                echo "VPN started and firewall restarted."
                ;;
            5)
                # Exit the script without stopping the firewall
                echo "Exiting without stopping the firewall."
                break
                ;;
            *)
                echo "Invalid option selected. Please try again."
                ;;
        esac
    done
}

# Start the firewall function to manage the rules or stop it
firewall
