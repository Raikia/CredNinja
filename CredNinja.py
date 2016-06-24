#!/usr/bin/env python3

import argparse
import sys
import os
import shutil
import threading
import queue
import re
import subprocess
import collections
import random
import time
import datetime


output_file_lock = threading.Lock()
output_file_handler = None
credQueue = queue.Queue()



list_of_codes = collections.OrderedDict([('LOGON_FAILURE',                'Invalid Creds'),
                                         ('ACCESS_DENIED',                'Valid'),
                                         ('STATUS_UNSUCCESSFUL',          'Unsuccessful connection'),
                                         ('STATUS_NETWORK_UNREACHABLE',   'Network Unreachable'),
                                         ('STATUS_INVALID_PARAMETER_MIX', 'Invalid PW/Hash'),
                                         ('STATUS_BAD_NETWORK_NAME',      'Invalid host'),
                                         ('STATUS_IO_TIMEOUT',            'IO Timeout on target'),
                                         ('STATUS_CONNECTION_RESET',      'Connection reset'),
                                         ('OS=',                          'LOCAL ADMIN! Valid')
                                       ])


settings = {'os': False,
            'domain': False,
            'timeout': 15,
            'delay': None,
            'users': False,
            'users_time': 100
           }


# Regexes
dateRegex = re.compile("([a-zA-Z]{3}\s+[0-9]{1,2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}\s[0-9]{4})\s*$")
usernameRegex = re.compile("(^\s+[a-zA-Z0-9\.\s]+)\sD\s")
os_reg = re.compile("OS=\[([^\]]+)\]")
domain_reg = re.compile("Domain=\[([^\]]+)\]")
regResult = re.compile("NT_([a-zA-Z_]*)")




def main():
    global output_file_handler, settings
    print("""


	 .d8888b.                       888 888b    888 d8b           d8b          
	d88P  Y88b                      888 8888b   888 Y8P           Y8P          
	888    888                      888 88888b  888                            
	888        888d888 .d88b.   .d88888 888Y88b 888 888 88888b.  8888  8888b.  
	888        888P"  d8P  Y8b d88" 888 888 Y88b888 888 888 "88b "888     "88b 
	888    888 888    88888888 888  888 888  Y88888 888 888  888  888 .d888888 
	Y88b  d88P 888    Y8b.     Y88b 888 888   Y8888 888 888  888  888 888  888 
	 "Y8888P"  888     "Y8888   "Y88888 888    Y888 888 888  888  888 "Y888888 
	                                                              888          
	                                                             d88P          
	                                                           888P"           

                    v2.0 (Built 6/24/2016) - Chris King (@raikiasec)
""")
    args = parse_cli_args()
    settings['os'] = args.os
    settings['domain'] = args.domain
    settings['timeout'] = args.timeout
    settings['delay'] = args.delay
    settings['users'] = args.users
    settings['users_time'] = args.users_time
    hosts_to_check = []
    creds_to_check = []
    mode = 'all'
    if os.path.isfile(args.accounts):
        with open(args.accounts) as accountfile:
            for line in accountfile:
                if line.strip():
                    parts = line.strip().split(args.passdelimiter,1)
                    if len(parts) != 2:
                        print("ERROR: Credential '" + line.strip() + "' did not have the password delimiter")
                        sys.exit(1)
                    creds_to_check.append(parts)
    else:
        parts = args.accounts.strip().split(args.passdelimiter,1)
        if len(parts) != 2:
            print("ERROR: Credential '" + args.accounts.strip() + "' did not have the password delimiter")
            sys.exit(1)
        creds_to_check.append(parts)

    if os.path.isfile(args.servers):
        with open(args.servers) as serverfile:
            for line in serverfile:
                if line.strip():
                    hosts_to_check.append(line.strip())
    else:
        hosts_to_check.append(args.servers)
    if len(hosts_to_check) == 0 or len(creds_to_check) == 0:
        print("ERROR: You must supply hosts and credentials at least!")
        sys.exit(1)
    
    mode = 'a'
    if args.invalid:
        mode = 'i'
    if args.valid:
        mode = 'v'
    if args.invalid and args.valid:
        mode = 'a'

    if args.output:
        output_file_handler = open(args.output, 'w')
    
    command_list = ['smbclient', '-U', '', '', '', '-c', 'dir']
    if args.ntlm and shutil.which('pth-smbclient') is None:
        print("ERROR: pth-smbclient is not found!  Make sure you install it (or use Kali!)")
        sys.exit(1)
    elif args.ntlm:
        command_list[0] = 'pth-smbclient'
        command_list.append('--pw-nt-hash')
    passwd_header = 'Password'
    if command_list[0] == 'pth-smbclient':
        passwd_header = 'Hash'

    if (len(hosts_to_check) * len(creds_to_check)) < args.threads:
        args.threads = len(hosts_to_check) * len(creds_to_check)

    try:
        if args.stripe == None:
            for host in hosts_to_check:
                for cred in creds_to_check:
                    credQueue.put([host, cred])
        else:
            if len(hosts_to_check) < len(creds_to_check):
                print("ERROR: For striping to work, you must have the same number or more hosts than you do creds!")
                sys.exit(1)
            if (len(creds_to_check) < args.threads):
                args.threads = len(creds_to_check)
            random.shuffle(hosts_to_check)
            for i in range(len(creds_to_check)):
                credQueue.put([hosts_to_check[i], creds_to_check[i]])

        if settings['os'] or settings['domain'] or settings['users']:
            print("%-35s %-35s %-35s %-25s %s" % ("Server", "Username", passwd_header, "Response", "Info"))
        else:
            print("%-35s %-35s %-35s %-25s" % ("Server", "Username", passwd_header, "Response"))
        print("------------------------------------------------------------------------------------------------------------------------------------------------------")

        thread_list = []
        for i in range(args.threads):
            thread_list.append(CredThread(mode, command_list))
        for t in thread_list:
            t.daemon = True
            t.start()

        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        print("\nQuitting!")
        sys.exit(1)
    if output_file_handler is not None:
        output_file_handler.close()


def search_users(command,output_from_previous):
    if ' Users ' in output_from_previous:
        command[6] = 'cd "Users";dir'
    elif ' Documents and Settings ' in output_from_previous:
        command[6] = 'cd "Documents and Settings";dir'
    now = datetime.datetime.now()
    p = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    total_users = []
    try:
        raw_output,errors = p.communicate(timeout=settings['timeout'])
        output = raw_output.decode('utf-8')
        for line in output.splitlines():
            if ' D ' in line and not re.match("^\s+\.", line):
                date_group = dateRegex.search(line)
                if (date_group is not None):
                    date_obj = datetime.datetime.strptime(date_group.group(1), '%b %d %H:%M:%S %Y')
                    diff = now - date_obj
                    if (diff.days < settings['users_time']):
                        user_group = usernameRegex.search(line)
                        if (user_group is not None):
                            username = user_group.group(1).strip()
                            add_sorted_users(username, diff.days, total_users)
        result_arr = []
        for user in total_users:
            result_arr.append(user[0] + ' ('+str(user[1])+')')
        if len(result_arr) == 0:
            result_arr.append('None within '+ str(settings['users_time']) +' days')
        return '(users=' + str(','.join(result_arr)) + ')'
    except Exception as e:
        return '(users=Timed out getting users)'


def add_sorted_users(user, days, full_list):
    for i in range(len(full_list)):
        if full_list[i][1] > days:
            full_list.insert(i, [user, days])
            return
    full_list.append([user,days])
    


def run_check(mode, stock_command, system, cred):
    command = stock_command[:]
    command[2] = cred[0]
    command[3] = '\\\\'+system+'\\c$'
    command[4] = cred[1]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    res = ('','','')
    try:
        raw_output,errors = p.communicate(timeout=settings['timeout'])
        output = raw_output.decode('utf-8')
        res = check_result(output)
    except:
        res = ['Unknown', 'Timed out', '']
        output = ''

    if 'LOCAL ADMIN' in res[1] and settings['users']:
        res[2] += search_users(command[:],output)
    out_string = ''
    if res[2] == '':
        out_string = "%-35s %-35s %-35s %-25s" % (system, cred[0], cred[1], res[1])
    else:
        out_string = "%-35s %-35s %-35s %-25s %s" % (system, cred[0], cred[1], res[1], res[2])

    if (mode == 'a' or mode == 'i') and 'Valid' not in res[1]:
        print(out_string)
        write_output(out_string)
    
    if (mode == 'a' or mode == 'v') and 'Valid' in res[1]:
        print(out_string)
        write_output(out_string)



def check_result(output):
    global list_of_codes
    add_on = ''
    if settings['os']:
        matches = os_reg.search(output)
        if matches is not None:
            add_on = '(os=' + matches.group(1) + ')'
    if settings['domain']:
        matches = domain_reg.search(output)
        if matches is not None:
            add_on += '(domain=' + matches.group(1) + ')'
    for code in list_of_codes.keys():
        if code in output:
            return [code, list_of_codes[code],add_on]

    matches = regResult.search(output)
    if matches is not None:
        return [matches.group(1), 'Unknown Error: ' + matches.group(1), add_on]
    return ['Unknown', 'No Data', add_on]

def write_output(text):
    global output_file_handler
    if output_file_handler is None:
        return
    output_file_lock.acquire()
    output_file_handler.write(text+"\n")
    output_file_lock.release()


def parse_cli_args():
    parser = argparse.ArgumentParser(add_help=False, description='Quickly check the validity of multiple user credentials across multiple servers and be notified if that user has local administrator rights on each server.')

    mandatory_args = parser.add_argument_group('Required Arguments')
    mandatory_args.add_argument('-a','--accounts', default=None, required=True, metavar='accounts_to_test.txt', help='A word or file of user credentials to test. Usernames are accepted in the form of "DOMAIN\\USERNAME:PASSWORD"')
    mandatory_args.add_argument('-s', '--servers', default=None, required=True, metavar='systems_to_test.txt', help='A word or file of servers to test against. Each credential will be tested against each of these servers by attempting to browse C$ via SMB')
 
    optional_args = parser.add_argument_group('Optional Arguments')
    optional_args.add_argument('-t', '--threads', default=10, type=int, help='Number of threads to use. Defaults to 10')
    optional_args.add_argument('--ntlm', default=False, action='store_true', help='Treat the passwords as NTLM hashes and attempt to pass-the-hash!')
    optional_args.add_argument('--valid', default=None, action='store_true', help='Only print valid/local admin credentials')
    optional_args.add_argument('--invalid', default=None, action='store_true', help='Only print invalid credentials')
    optional_args.add_argument('-o', '--output', default=None, help='Print results to a file')

    optional_args.add_argument('-p', '--passdelimiter', default=':', help='Change the delimiter between the account username and password. Defaults to ":"')


    optional_args.add_argument('--delay', default=None, type=int, nargs=2, metavar=('SECONDS', '%JITTER'), help='Delay each request per thread by specified seconds with jitter (example: --delay 20 10, 20 second delay with 10%% jitter)')
    optional_args.add_argument('--timeout', default=15, type=int, help='Amount of seconds wait for data before timing out.  Default is 15 seconds')
    optional_args.add_argument('--stripe', default=None, action='store_true', help='Only test one credential on one host to avoid spamming a single system with multiple login attempts (used to check validity of credentials). This will randomly select hosts from the provided host file.')
    optional_args.add_argument('-h', '--help', action='help', help='Get help about this script\'s usage')
    
    additional_args = parser.add_argument_group('Additional Information Retrieval')
    additional_args.add_argument('--os', default=False, action='store_true', help='Display the OS of the system if available (no extra packet is being sent)')
    additional_args.add_argument('--domain', default=False, action='store_true', help='Display the primary domain of the system if available (no extra packet is being sent)')
    additional_args.add_argument('--users', default=False, action='store_true', help='List the users that have logged in to the system in the last 6 months (requires LOCAL ADMIN). Returns usernames with the number of days since their home directory was changed')
    additional_args.add_argument('--users-time', default=100, type=int, help='Modifies --users to search for users that have logged in within the last supplied amount of days (default 100 days)')
    args = parser.parse_args()
    if args.accounts is None or args.servers is None:
        parser.print_help()
        sys.exit()
    return args



class CredThread (threading.Thread):
    def __init__(self, mode, stock_cmd):
        threading.Thread.__init__(self)
        self.mode = mode
        self.stock_cmd = stock_cmd

    def run(self):
        queue_arr = []
        try:
            first = True
            while True:
                queue_arr = credQueue.get(False)
                if queue_arr is None:
                    break
                if not first and settings['delay'] is not None:
                    minTime = ((100-settings['delay'][1])/100) * settings['delay'][0]
                    sleeptime = random.random() * ( settings['delay'][0] - minTime) + minTime
                    time.sleep(sleeptime)
                run_check(self.mode, self.stock_cmd, queue_arr[0], queue_arr[1])
                first = False
                time.sleep(0.01)
        except queue.Empty as e:
            return




if __name__ == '__main__':
    main()







