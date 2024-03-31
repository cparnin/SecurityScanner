#!/usr/bin/python3

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
import argparse
from urllib.parse import urlparse
from datetime import datetime
import json

##############################  GLOBALS #######################################

load_dotenv() # Load environment variables from .env file

############################## FUNCTIONS ######################################

def shodan_search(search_term):
    api_key = os.environ.get('SHODAN_API_KEY') # Get API key from environment variable
    api = shodan.Shodan(api_key)
    datetime_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"shodan_search_{datetime_stamp}.json"

    try:
        results = api.search(search_term)
        with open(output_file, 'w') as file:
            json.dump(results, file, indent=4)
        print("Results saved to {output_file}")
    except shodan.APIError as e: 
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
        print("0. Shodan Recon")
        print("1. Nmap Vulners Scan")
        print("exit. Exit")
        choice = input("Enter your choice: ")

        if choice == '0':
            shodan_search(input("Enter search term: "))
        elif choice == '1':
            nmap_vulners_scan(input("Enter target IP or URL: "))
        elif choice == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()