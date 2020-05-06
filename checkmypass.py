#Libraries required to run

import requests
import hashlib
import sys


# Request info from API

def request_api_data(head_check):
    url = 'https://api.pwnedpasswords.com/range/' + head_check
    leaks = requests.get(url)

    if leaks.status_code != 200:
        raise RuntimeError(f' Error fetching: {leaks}, check api functions and try again')

    # return leaks from query run
    return leaks


# Compare results received from API

def leak_check(hashes, tail_check):
    # hashes are the responses received from the api data check
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == tail_check:
            return count
    return 0


# Convert password to sha1 to check against API data

def pwned_pass_check(password):
    # convert to Sha1 for comparison
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())

    # split into head to grab api leaks and tail to compare with results returned from leak
    head, tail = sha1password[:5], sha1password[5:]

    response = request_api_data(head)
    return leak_check(response, tail)


# main function accepts arguments from terminal. Pass in as many passwords as you may want

def main(args):
    for password in args:
        count = pwned_pass_check(password)
        if count:
            print(f'The password {password[0:3]}{len(password) * "*"} was found {count} times. Please reconsider!')
        else:
            print(f'Password {password[0:3]}{len(password) * "*"} NOT found! Please proceed!')
    return 'Password Check Complete!'


# call main function and feed in the password you would like to check
# can take in multiple passwords

if __name__ == '__main__':
    # ensure at least one argument is passed, if not exit
    try:
        argv1 = sys.argv[1]
    except IndexError:
        print('No passwords to check - exiting screen')
        sys.exit()

    sys.exit(main(sys.argv[1:]))
