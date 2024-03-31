#!/webapp/webappenv/bin/python3

##############################  NOTES #######################################

'''
Python Virtual Environment Instructions:
    Create:
        go into specific project directory
        python -m venv <venv_name> # create virtual environment
        source <venv_name>/bin/activate
        pip install <package_names>
        pip freeze > requirements.txt # save all installed packages to a file
    Activate:
        source <venv_name>/bin/activate
        pip install -r requirements.txt
        might have to change interpreter to:
            /Users/parninc/Desktop/PythonSecurity/webapp/webappenv/bin/python3
'''
            
##############################  IMPORTS #######################################

import subprocess
import socket
from urllib.parse import urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import time 
import shodan
import json
import logging

logging.basicConfig(level=logging.DEBUG)

############################## RECON ######################################

def shodan_search(search_term):
    api_key = "o8eFzWoLQhEBfi62j9xLbDdFeTOcLbGt" # Replace with your actual API key
    api = shodan.Shodan(api_key)
    datetime_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"shodan_search_{datetime_stamp}.json"

    try:
        results = api.search(search_term)
        with open(output_file, 'w') as file:
            json.dump(results, file, indent=4)
        print("Results saved to {output_file}")    
    except shodan.APIError as e: 
        print('Error: {}'.format(e))

def spiderfoot_recon(target):
    '''
    https://github.com/smicallef/spiderfoot
    manual setup (but we start it via subprocess below):
        git clone spiderfoot
        run python sf.py -l 127.0.0.1:5001 in spiderfoot dir
        browse to it
    '''
    spiderfoot_server = "http://127.0.0.1:5001"
    api_key = "YOUR_API_KEY"  # Replace with your actual API key, if required
    spiderfoot_path = "/Users/parninc/tools/spiderfoot/sf.py"  # Replace with the actual path
    
    # Start SpiderFoot server
    subprocess.Popen(["python", spiderfoot_path, "-l", "127.0.0.1:5001"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Give the server some time to start

    # Initiate a new scan
    start_scan_endpoint = f"{spiderfoot_server}/startscan?target={target}&module=ALL&apikey={api_key}"
    response = requests.get(start_scan_endpoint)
    scan_id = response.json()['scan_id']
    
    # Check scan status until it's finished
    status_endpoint = f"{spiderfoot_server}/scanstatus?scanId={scan_id}&apikey={api_key}"
    status = ""
    while status != "FINISHED":
        time.sleep(5)  # Poll every 5 seconds
        status_response = requests.get(status_endpoint)
        status = status_response.json()['status']
    
    # Retrieve the results
    results_endpoint = f"{spiderfoot_server}/scanresults?scanId={scan_id}&apikey={api_key}"
    results_response = requests.get(results_endpoint)
    results_data = results_response.json()

    # Save the results to a file with a timestamp
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f"spiderfoot_results_{timestamp}.json"
    with open(filename, 'w') as outfile:
        json.dump(results_data, outfile)

    print(f"Results saved to {filename}")
    return filename

############################## SCANNING ######################################

def nmap_vulners_scan(target):
    # Resolve URL to IP if needed
    if target.startswith("http://") or target.startswith("https://"):
        domain = urlparse(target).netloc
        try:
            target = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"Could not resolve {domain}")
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
        print("1. Spiderfoot Recon")
        print("2. Nmap Vulners Scan")
        print("exit. Exit")
        choice = input("Enter your choice: ")

        if choice == '0':
            shodan_search(input("Enter search term: "))
        elif choice == '1':
            spiderfoot_recon(input("Enter email address: "))
        elif choice == '2':
            nmap_vulners_scan(input("Enter target IP or URL: "))
        elif choice == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()