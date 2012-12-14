#!/usr/bin/python

import os
import sys
import argparse
import json
import getpass

import requests

github_api_endpoint = 'https://api.github.com'

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--private', '-p',
            action='store_true',
            default=False)
    p.add_argument('--description', '-d')
    p.add_argument('--login', '-L', action='store_true')
    p.add_argument('--logout', '-O', action='store_true')
    p.add_argument('--anonymous', '-a', action='store_true')
    p.add_argument('--credentials', '-C',
            default=os.path.join(os.environ['HOME'], '.github_oauth_token'))
    p.add_argument('files', nargs='*')
    return p.parse_args()

def cmd_gist(opts):
    headers = {}

    if not opts.anonymous and os.path.isfile(opts.credentials):
        with open(opts.credentials) as fd:
            token = fd.read()
            headers['Authorization'] = 'token %s' % token

    data = {
            'public': not opts.private,
            'files': {},
            }

    if opts.description:
        data['description'] = opts.description

    if opts.files:
        for file in opts.files:
            with open(file) as fd:
                data['files'][os.path.basename(file)]= {
                        'content': fd.read(),
                        }
    else:
        data['files']['stdin'] = {
                'content': sys.stdin.read(),
                }

    r = requests.post(
            '%s/gists' % github_api_endpoint,
            headers=headers,
            data=json.dumps(data))

    r = json.loads(r.text)
    print r['html_url']

def cmd_login(opts):
    data = {
            'scopes': ['gist'],
            'note': 'gist command line tool',
            }

    print 'Your github username: ',
    user = sys.stdin.readline().strip()
    passwd = getpass.getpass('Your github password: ')

    r = requests.post('%s/authorizations' % github_api_endpoint,
            data=json.dumps(data),
            auth=(user, passwd))
    
    r = json.loads(r.text)

    if 'token' in r:
        with open(opts.credentials, 'w') as fd:
            fd.write(r['token'])

        print 'You are logged in.'
    else:
        print 'Login failed: %(message)s' % r
        sys.exit(1)

def cmd_logout(opts):
    os.unlink(opts.credentials)
    print 'You are logged out.'

def main():
    opts = parse_args()

    if opts.login:
        cmd_login(opts)
    elif opts.logout:
        cmd_logout(opts)
    else:
        cmd_gist(opts)

if __name__ == '__main__':
    main()


