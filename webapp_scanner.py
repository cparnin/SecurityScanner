#!/usr/bin/env python3

##############################  NOTES #######################################

'''
test
'''
            
##############################  IMPORTS #######################################

import subprocess
import os
from dotenv import load_dotenv
import shodan
import socket
from urllib.parse import urlparse
from datetime import datetime
import json

##############################  GLOBALS #######################################

load_dotenv() # Load environment variables from .env file

############################## FUNCTIONS ######################################

def dig(hostname):
    commands = [
        f"dig {hostname} A +short",
        f"dig {hostname} MX +short",
        f"dig {hostname} NS +short",
        f"dig {hostname} TXT +short"
    ]    
    results = {}
    # Discover nameservers
    try:
        ns_output = subprocess.check_output(f"dig {hostname} NS +short", shell=True).decode().strip()
        nameservers = ns_output.splitlines()  
        if nameservers:
            first_nameserver = nameservers[0]
        else:
            raise ValueError("No nameservers found")
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving nameservers: {e}")
        first_nameserver = None  

    # AXFR attempt (if nameserver was retrieved)
    if first_nameserver:
        commands.append(f"dig {hostname} AXFR @{first_nameserver}")  

    # Execute DIG commands
    for command in commands:
        try:
            output = subprocess.check_output(command, shell=True).decode().strip()
            record_type = command.split()[1]  
            results[record_type] = output 
        except subprocess.CalledProcessError as e:
            if "Transfer failed" in str(e):  
                results['AXFR'] = "Zone transfer likely not allowed"
            else:
                print(f"An error occurred during DIG command: {e}")

def shodan_search(search_term):
    api_key = os.environ.get('SHODAN_API_KEY') # Get API key from environment variable
    api = shodan.Shodan(api_key) # Create API object
    datetime_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"shodan_search_{datetime_stamp}.json"

    try:
        results = api.search(search_term)
        with open(output_file, 'w') as file:
            json.dump(results, file, indent=4)
        print("Results saved to {output_file}")

        print("---- Top Results ----")  # Example extraction
        for match in results['matches'][:5]:  # Limit to top 5 for brevity
            ip_str = match['ip_str']
            port = match['port']
            org = match.get('org', 'Not Available') 
            hostnames = match['hostnames']
            print(f"IP: {ip_str}, Port: {port}, Organization: {org}, Hostnames: {hostnames}")
    except shodan.APIError as e: # Handle API errors
        print(f"Error during Shodan search for '{search_term}': {e}")

def nmap_vulners_scan(target):
    # Resolve URL to IP if needed
    if target.startswith("http://") or target.startswith("https://"):
        domain = urlparse(target).netloc
        try:
            target = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"Error resolving domain '{domain}': DNS lookup failed")
            return
        
    datetime_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"nmap_scan_{datetime_stamp}.txt"
    try:
        # -oN = output to file
        command = ["nmap", "-sV", "--script=vulners", "-oN", output_file, target]
        subprocess.run(command, check=True)
        print(f"Scan results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during Nmap scan: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

################################## MAIN #########################################

def main():
    while True:
        print("\nWelcome to My Vulnerability Scanner! Please choose an option:")
        print("0. Dig Command")
        print("1. Shodan Recon")
        print("2. Nmap Vulners Scan")
        print("exit. Exit")
        choice = input("Enter your choice: ")

        if choice == '0':
            dig(input("Enter hostname: "))
        elif choice == '1':
            shodan_search(input("Enter search term: "))
        elif choice == '2':
            nmap_vulners_scan(input("Enter target IP or URL: "))
        elif choice == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()