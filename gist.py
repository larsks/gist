#!/usr/bin/python

import argparse
import getpass
import github
import json
import logging
import os
import subprocess
import sys
import urlparse


LOG = logging.getLogger('gist')

args = None
cfg = None
app_name = 'com.oddbit.gist'
default_config_file = os.path.join(os.environ['HOME'],
                                   '.github')


class GistError(Exception):
    pass


class AuthenticationFailed(GistError):
    pass


def get_config_value(arg_name, cfg_name, env_name, prompt,
                     password=False):
    LOG.debug('getting config value %s %s %s',
              arg_name, cfg_name, env_name)
    if getattr(args, cfg_name, None):
        return getattr(args.cfg_name)
    elif cfg_name in cfg.get('github', {}):
        return cfg['github'][cfg_name]
    elif env_name in os.environ:
        return os.environ[env_name]
    else:
        if password:
            val = getpass.getpass(prompt=prompt)
        else:
            print prompt,
            val = sys.stdin.readline()

        return val.rstrip()


def do_github_login():
    global args

    user = get_config_value(
        'user', 'user', 'GITHUB_USER',
        'GitHub username: ')
    password = get_config_value(
        'password', 'password', 'GITHUB_PASSWORD',
        'GitHub password: ',
        password=True)

    LOG.debug('got username = %s', user)
    LOG.debug('got password = %s (masked)',
              'X' * len(password))

    try:
        gh = github.Github(user, password)
        gu = gh.get_user()

        for auth in gu.get_authorizations():
            if auth.note == app_name:
                LOG.warn('using existing authentication token %s (%s)',
                         auth.id, auth.note)
                break
        else:
            auth = gu.create_authorization(scopes=['gist'],
                                           note=app_name)
            LOG.warn('created new authentication token %s (%s)',
                     auth.id, auth.note)
    except github.BadCredentialsException:
        raise AuthenticationFailed('Authentication failed. Check your '
                                   'username and password.')

    if 'github' not in cfg:
        cfg['github'] = {}

    cfg['github']['auth_id'] = auth.id
    cfg['github']['auth_token'] = auth.token
    with open(args.config, 'w') as fd:
        fd.write(json.dumps(cfg))


def do_create_gist():
    try:
        gh = github.Github(login_or_token=cfg['github']['auth_token'])
    except KeyError:
        raise AuthenticationFailed('You must log in using --login first')

    gu = gh.get_user()

    files = {}
    if args.files:
        for filename in args.files:
            LOG.debug('reading content from file %s', filename)
            with open(filename) as fd:
                files[os.path.basename(filename)] = github.InputFileContent(
                    fd.read())
    else:
        LOG.debug('reading content from stdin')
        files[args.filename if args.filename else 'stdin'] = \
            github.InputFileContent(sys.stdin.read())

    description = args.description if args.description else ''

    try:
        gist = gu.create_gist(not args.private, files,
                              description=description)
    except github.BadCredentialsException:
        raise AuthenticationFailed(
            'Failed to create gist (authentication failed). '
            'Try logging in with --login.')
    else:
        print gist.html_url

        if args.clone:
            LOG.info('cloning gist %s into local repository',
                     gist.id)
            subprocess.call([
                'git', 'clone', '-q',
                gist.git_pull_url,
                'gist-%s' % gist.id])

            if args.ssh:
                LOG.info('configuring remote origin to use ssh for push')
                push_url = urlparse.urlparse(gist.git_push_url)
                ssh_url = 'git@%s:%s' % (
                    push_url.netloc, push_url.path)
                os.chdir('gist-%s' % gist.id)
                subprocess.call([
                    'git', 'remote', 'set-url',
                    '--push', 'origin', ssh_url])

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--config', '-f',
                   default=default_config_file)
    p.add_argument('--clone', '-c',
                   action='store_true')
    p.add_argument('--private', '-P',
                   action='store_true')
    p.add_argument('--description', '-d')
    p.add_argument('--filename', '-n')
    p.add_argument('--ssh', '-s',
                   action='store_true')

    g = p.add_argument_group('Authentication options')
    g.add_argument('--login', '-l',
                   action='store_true')
    g.add_argument('--user', '-u')
    g.add_argument('--password', '--pass', '-p')

    g = p.add_argument_group('Logging options')
    g.add_argument('--verbose', '-v',
                   action='store_const',
                   const=logging.INFO,
                   dest='loglevel')
    g.add_argument('--debug',
                   action='store_const',
                   const=logging.DEBUG,
                   dest='loglevel')
    p.add_argument('files', nargs='*')
    p.set_defaults(loglevel=logging.WARN)
    return p.parse_args()


def main():
    global args
    global cfg

    args = parse_args()
    logging.basicConfig(
        level = args.loglevel)

    try:
        with open(args.config) as fd:
            cfg = json.load(fd)
    except IOError:
        cfg = {}

    if args.login:
        do_github_login()
    else:
        do_create_gist()


if __name__ == '__main__':
    try:
        main()
    except GistError as err:
        LOG.error(err)
        sys.exit(1)
