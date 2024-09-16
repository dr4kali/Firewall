# Firewall Script Setup Guide

This guide will walk you through installing all the necessary packages and dependencies to run the firewall script, modify rules, and view logs in real-time using a GUI.

## System Requirements

Before running the firewall script, ensure your system meets the following requirements:
- RHEL-based Linux distribution (CentOS, Fedora, etc.)
- Python 3 installed


## Add the epel-release to repository (for RHEL9)

```
#enable epel-release for RHEL 9
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
```
## Necessary Packages

The following packages are required for the firewall to function properly:

### 1. **Iptables**
`iptables` is used to set up rules for packet interception via the NFQUEUE. Install it with the following command:

```
sudo yum install iptables
```

### 2. **Python 3**

Ensure Python 3 is installed on your system for running the firewall and logging scripts.

```
sudo yum install python3
```

### 3. Dev tools

The `libnetfilter_queue` package is required to facilitate communication between Netfilter (in the Linux kernel) and the Python firewall script. Install it using:

```
sudo yum install libnetfilter_queue-devel
sudo yum groupinstall "Development Tools"
sudo yum update
```

### 4. **Vim**

The `vim` editor is used to modify the firewall rules file (`firewall_rules.txt`) interactively from the command-line menu.

```
sudo yum install vim
```

### 5. Python packages

Use the following command to install all the required Python packages at once:

```
pip install -r requirements.txt
```

## How to Set Up

1. **Clone or download the firewall script and the accompanying files** (like `firewall.py`, `firewall_rules.txt`, and `gui_logger.py`).
    
2. **Ensure that all the necessary packages are installed** by following the commands mentioned above.
    
3. **Run the setup script**:
    `./firewall.sh`
    This script sets up the firewall, provides a menu to manage rules, and allows you to view logs in real-time.

## Troubleshooting

- **Permission Issues**: If you encounter permission issues with `iptables` or `NetfilterQueue`, ensure you are using `sudo` for administrative tasks.
    
- **Missing Dependencies**: If any of the packages fail to install, check if your system's repositories are up to date by running:
    `sudo yum update`
    
- **Flushing Firewall Rules**: Be careful when stopping the firewall. The `iptables -F` command will flush all firewall rules, which might disrupt other configurations.