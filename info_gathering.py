import sys
import whois
import dns.resolver
import shodan
import requests
import argparse
import socket

argparse = argparse.ArgumentParser(description="THis is a basic information gathering Tool", usage="Python3 info_gathering.py -d DOMAIN [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter The domain for footprinting" , required=True)
argparse.add_argument("-s", "--shodan", help="Enter The IP for shodan search")
argparse.add_argument("-o", "--output", help="Enter The file name")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan
output = args.output

# whois module
print("Getting Info....")
# using whois library, creating instance
py = whois.query(domain)
print("[+]whois info found.")
whois_result = ''
try:
    py = whois.query(domain)
    print("[+] whois info is found")
    whois_result += "Name: {}".format(py.name) + '\n'
    whois_result += "Registrar: {}".format(py.registrar) + '\n'
    whois_result += "Creation Date: {}".format(py.creation_date) + '\n'
    whois_result += "Expiration date: {}".format(py.expiration_date) + '\n'
    whois_result += "Registrant: {}".format(py.registrant) + '\n'
    whois_result += "registrant Country: {}".format(py.registrant_country) + '\n'
except:
    pass
print(whois_result)

#DNS module
print("[+] Getting DNS info.. ")
dns_result = ''
#implementing dns.resolver from dnspython
try:
    for a in dns.resolver.resolve(domain, 'A'):
        dns_result += "[+] A Record {}".format(a.to_text()) + '\n'
    for a in dns.resolver.resolve(domain, 'NS'):
        dns_result += "[+] NS Record {}".format(a.to_text()) + '\n'
    for a in dns.resolver.resolve(domain, 'MX'):
        dns_result += "[+] MX Record {}".format(a.to_text()) + '\n'
    for a in dns.resolver.resolve(domain, 'TXT'):
        dns_result += "[+] TXT Record {}".format(a.to_text()) + '\n'
except:
    pass
print(dns_result)

#Geolocation module
print("[+] Getting geolocation info..")
geo_result = ''

#implementing request for web request
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    geo_result += "[+] Country: {}".format(response['country_name']) + '\n'
    geo_result += "[+] Latitude: {}".format(response['latitude']) + '\n'
    geo_result += "[+] Longitude: {}".format(response['longitude']) + '\n'
    geo_result += "[+] City: {}".format(response['city']) + '\n'
    geo_result += "[+] State: {}".format(response['state']) + '\n'
except:
    pass
print(geo_result)

#Shodan module
# if ip:
#     print("[+] Getting Info for Shodan for IP {}".format(ip))
#     #shodan API
#     api = shodan.Shodan("f5fW4gvLkg0bTf46KICRJGnqXupWApwh")
#     try:
#         results = api.search(ip)
#         print("[+] Result found: {}".format(results['total']))
#         for result in results['matches']:
#             print("[+] IP: {}".format(result['ip_str']))
#             print("[+] Data: \n{}".format(result['data']))
#             print()
#
#     except:
#         print("[+] Shodan search error...:(")
def shodan_info(ip):
    print("[+] Getting Shodan Info....")
    if not ip:
        print("[-] No IP address provided.")
        return

    print("[+] Getting Info for Shodan for IP {}".format(ip))

    # Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
    api_key = 'f5fW4gvLkg0bTf46KICRJGnqXupWApwh'

    api = shodan.Shodan(api_key)

    try:
        results = api.search(ip)
        print("[+] Total results found: {}".format(results['total']))

        for result in results['matches']:
            print("\n[+] IP: {}".format(result['ip_str']))
            print("[+] Data: \n{}".format(result['data']))

    except shodan.exception.APIError as e:
        print("[-] Shodan API error: {}".format(e))

    except Exception as e:
        print("[-] An unexpected error occurred: {}".format(e))


# Example usage:
ip_to_search = ip
shodan_info(ip_to_search)


# Save the output
if (output):
    with open(output, 'w') as file:
        file.write(whois_result + '\n\n')
        file.write(dns_result+ '\n\n')
        file.write(geo_result+ '\n\n')



