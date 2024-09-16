#!/bin/bash

# Set up iptables rules for NFQUEUE
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

# Start the Python firewall script in the background
sudo python3 firewall.py &  # Run the firewall in the background

LOG_FILE="firewall_log.txt"  # Define the log file location (should match the Python script's logging)

# Function to handle the firewall operations
firewall(){
    while true; do
        echo "Select an Operation"
        echo "1. Add or Remove Firewall Rules"
        echo "2. Stop the Firewall"
        echo "3. View Logs in Real-Time"
        echo "4. Exit"
        read -p "Enter the number: " op
        
        case $op in
            1)
                # Open the firewall rules file in vim to add or remove rules
                sudo vim firewall_rules.txt
                ;;
            2)
                # Stop the firewall by killing the Python process and flushing iptables
                echo "Stopping the firewall..."
                sudo pkill -f firewall.py
                sudo iptables -F  # Flush all iptables rules
                echo "Firewall stopped."
                break
                ;;
            3)
                # Display the logs in real-time and trap the Ctrl+C signal to return to the menu
                echo "Displaying logs in real-time. Press Ctrl+C to return to the menu."
                trap '' SIGINT  # Ignore Ctrl+C signal while tailing logs
                sudo tail -f "$LOG_FILE"  # View logs in real-time
                trap - SIGINT  # Restore Ctrl+C signal handling after tail is done
                ;;
            4)
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
