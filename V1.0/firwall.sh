#!/bin/bash

# Setting up iptables for NFQUEUE
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

sudo python firewall.py

firewall() {
    while true; do
        echo "Select an Operation"
        echo "1. Add or Remove Firewall Rules"
        echo "2. Stop the Firewall"
        echo "3. View Logs in Real-Time"
        echo "4. Exit"
        read -p "Enter the number: " op

        case $op in
            1)
                vim firewall_rules.txt
                ;;
            2)
                echo "Stopping the firewall..."
                sudo iptables -D INPUT -j NFQUEUE --queue-num 0
                sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
                sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
                exit 0
                ;;
            3)
                echo "Displaying logs in real-time. Press Ctrl+C to return to the menu."
                sudo tail -f /var/log/firewall.log &  # Display logs in a background process
                LOG_PID=$!  # Capture the process ID
                trap "kill $LOG_PID" SIGINT  # Ensure the log process is stopped when Ctrl+C is pressed
                wait $LOG_PID  # Wait for the log process to finish
                ;;
            4)
                exit 0
                ;;
            *)
                echo "Invalid option, please try again."
                ;;
        esac
    done
}

firewall
