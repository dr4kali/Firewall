#!/bin/bash

# Function to manage the firewall and NFQUEUE setup
manage_firewall() {
    # Set up iptables rules for NFQUEUE
    sudo iptables -I INPUT -j NFQUEUE --queue-num 0
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
    sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

    # Start the Python firewall script in the background
    sudo python3 firewall.py &  # Run the firewall in the background
}

# Function to stop the firewall
stop_firewall() {
    echo "Stopping the firewall..."
    sudo pkill -f firewall.py
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
                sudo vim firewall_rules.txt
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

                # Wait for VPN to fully initialize
                sleep 10

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