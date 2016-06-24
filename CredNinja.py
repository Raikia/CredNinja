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


settings = {}




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

        if settings['os'] or settings['domain']:
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



def run_check(mode, stock_command, system, cred):
    command = stock_command[:]
    command[2] = cred[0]
    command[3] = '\\\\'+system+'\\c$'
    command[4] = cred[1]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    res = ('','','')
    try:
        output,errors = p.communicate(timeout=settings['timeout'])
        res = check_result(output.decode('utf-8'))
    except:
        res = ('Unknown', 'Timed out', '')
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
        os_reg = re.compile("OS=\[([^\]]+)\]")
        matches = os_reg.search(output)
        if matches is not None:
            add_on = '(os=' + matches.group(1) + ')'
    if settings['domain']:
        domain_reg = re.compile("Domain=\[([^\]]+)\]")
        matches = domain_reg.search(output)
        if matches is not None:
            add_on += '(domain=' + matches.group(1) + ')'
    for code in list_of_codes.keys():
        if code in output:
            return (code, list_of_codes[code],add_on)

    regResult = re.compile("NT_([a-zA-Z_]*)")
    matches = regResult.search(output)
    if matches is not None:
        return (matches.group(1), 'Unknown Error: ' + matches.group(1), add_on)
    return ('Unknown', 'No Data', add_on)

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







