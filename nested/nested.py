#!/usr/bin/env python3

import os
import json
import getpass
import argparse


def init_argparse():
    parser = argparse.ArgumentParser(description="Obtains all nested groups\
            for groups defined in SmartConsole Access Roles")
    requiredNamed = parser.add_argument_group("Required arguments")
    requiredNamed.add_argument('-mu', type=str, help="Mgmt API user", required=True)
    requiredNamed.add_argument('-mi', type=str, help="Mgmt/DMS IP", required=True)
    requiredNamed.add_argument('-li', type=str, help="LDAP Sever IP", required=True)
    requiredNamed.add_argument('-D', type=str, help="DN of an LDAP user", required=True)
    requiredNamed.add_argument('-b', type=str, help="Base DN for search", required=True)
    requiredNamed.add_argument('-p', type=str, help="LDAP Port", required=True)
    return parser


def fetch_roles(username, password, mgmt_ip):
    # Create directory that will have access roles and groups

    os.system('mgmt_cli show access-roles -u %s -p %s -d %s details-level "full" \
            --format json > /tmp/ar.json' % (username, password, mgmt_ip) )

    with open('/tmp/ar.json', 'r') as infile:
        contents = json.load(infile)

    objects = contents["objects"]

    for roles in objects:
        current_ar = roles['name']
        ar_groups[current_ar] = {}
        
        roles_string = roles["users"]

        if roles_string == "all identified" or roles_string == "any":

            ar_groups[current_ar][roles_string] = []

        else:

            for groups in roles["users"]:


                if groups["type"] == "CpmiAdGroup":
                    ar_groups[current_ar][groups['dn']] = []

                else:
                    continue

    
def nested_builder(memberof, results,role, dict_map):
    map = dict_map

    for main, nested in map.items():

        for result in results:
            member = result[0]

            if memberof in result:
                nested.append({member:[]})

        for i in nested:

            for main, nested in i.items():
                memberof = f"memberOf={main}" 
                nested_builder(memberof, results, role, i)
    

def ldap_query(user_dn, ldappass, basedn, dcip, port):
    for role, groups_list in ar_groups.items():

        for group in groups_list:
            os.system('ldapsearch -D %s -w %s -b %s -h %s -p %s \
                "(&(objectCategory=Group)\
                (memberOf:1.2.840.113556.1.4.1941:=%s))"\
                > /tmp/ldapquery.txt'\
                % (user_dn, ldappass, basedn, dcip, port, group))

            with open(f"/tmp/ldapquery.txt", "r") as infile:
                contents = infile.read()

            memberof = f'memberOf={group}'
            raw_results = contents.split(sep="\n\n")
            results = [i.split('\n') for i in raw_results]
            inital_map = ar_groups[role]
            nested_builder(memberof,results,role, inital_map )


def main():
    parser = init_argparse()
    args = parser.parse_args()
    sc_user_pass = getpass.getpass(prompt="SmartConsole User Password: ", stream=None)
    ldap_user_pass = getpass.getpass(prompt="LDAP User Password: ", stream=None)
    fetch_roles(args.mu, sc_user_pass, args.mi)
    ldap_query(args.D, ldap_user_pass, args.b, args.li, args.p)
    ar_json = json.dumps(ar_groups, indent=4)
    print(ar_json)


if __name__ == "__main__":
    ar_groups = {}
    main()
