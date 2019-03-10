#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview']
}

DOCUMENTATION = '''
---
module: bitbucket_hook

short_description: Manages bitbucket hooks

description:
- Will create/update/delete bitbucket webhooks
- Supports check mode.

version_added: "2.8"

author:
- Lucas Theisen (@lucastheisen)

requirements:
- python >= 2.7

extends_documentation_fragment:
- auth_basic

options:
  api_token:
    description:
    - Bitbucket token for logging in.
    type: str
  force_basic_auth:
    description:
    - The library used by the uri module only sends authentication information when a webservice responds to an initial request with a 401 status. Since some basic auth services do not properly send a 401, logins will fail. This option forces the sending of the Basic authentication header upon initial request.
    type: bool
    default: false
  hook_url:
    description:
    - The url that you want Bitbucket to post to.
    required: true
    type: str
  name:
    description:
    - The name of the hook.  Used as the key to lookup an existing webhook.
    required: true
    type: str
  project:
    description:
    - Key of the Bitbucket project.
    required: true
    type: str
  repo:
    description:
    - The name of the Bitbucket repository.
    required: true
    type: str
  state:
    description:
    - When C(present) the hook will be updated to match the input or created if it doesn't exist. When C(absent) it will be deleted if it exists.
    type: str
    default: present
    choices: [ "present", "absent" ]
  events:
    description:
    - List of events to trigger on
    type: list
    default:
    - "repo:refs_changed"
    choices: 
    - "pr:comment:added"
    - "pr:comment:edited"
    - "pr:comment:deleted"
    - "pr:declined"
    - "pr:deleted"
    - "pr:merged"
    - "pr:modified"
    - "pr:opened"
    - "pr:reviewer:approved"
    - "pr:reviewer:needs_work"
    - "pr:reviewer:unapproved"
    - "pr:reviewer:updated"
    - "repo:comment:added"
    - "repo:comment:deleted"
    - "repo:comment:edited"
    - "repo:forked"
    - "repo:modified"
    - "repo:refs_changed"
  token:
    description:
    - Secret token to validate hook messages at the receiver.
    required: false
    type: str
'''

EXAMPLES = '''
- name: Create new webhook for commits and merges
  bitbucket_webhook:
    api_password: "secret"
    api_username: "me"
    api_url: "https://bitbucket.example.com/rest/api/1.0"
    events:
    - repo:refs_changed
    - pr:merged
    force_basic_auth: true
    hook_url: "http://openshift.example.com/my-project/my-app"
    name: openshift_fun
    project: "MP"
    repo: "my-app"
    state: present
    token: "secrettosupplywithhook"
- name: Update the token
  bitbucket_webhook:
    api_password: "secret"
    api_username: "me"
    api_url: "https://bitbucket.example.com/rest/api/1.0"
    events:
    - repo:refs_changed
    - pr:merged
    force_basic_auth: true
    hook_url: "http://openshift.example.com/my-project/my-app"
    name: openshift_fun
    project: "MP"
    repo: "my-app"
    state: absent
    token: "newsecrettosupplywithhook"
- name: Delete the hook
  bitbucket_webhook:
    api_password: "secret"
    api_username: "me"
    api_url: "https://bitbucket.example.com/rest/api/1.0"
    events:
    - repo:refs_changed
    - pr:merged
    force_basic_auth: true
    hook_url: "http://openshift.example.com/my-project/my-app"
    name: openshift_fun
    project: "MP"
    repo: "my-app"
    state: absent
    token: "secrettosupplywithhook"
'''

RETURN = '''
diff:
  description: The changes that will be made
  returned: when differences were detected between task webhook and existing
  type: dict
existing:
  description: API object of existing entry
  returned: when exists prior to task
  type: dict
method:
  description: The type of action performed (create/update/delete)
  returned: when exists prior to task
  type: str
  sample: "create"
msg:
  description: Failure message
  returned: on failure
  type: str
  sample: "Unsupported parameters for (bitbucket_webhook) module: status Supported parameters include: api_password, api_token, api_url, api_username, events, force_basic_auth, hook_url, name, project, repo, state, token, validate_certs"
webhook:
  description: API object
  returned: when persisted to bitbucket
  type: dict
'''

import json

from ansible.module_utils.api import basic_auth_argument_spec
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils.urls import fetch_url

try:
    from urllib import quote_plus  # Python 2.X
except ImportError:
    from urllib.parse import quote_plus # Python 3+

# https://docs.atlassian.com/bitbucket-server/rest/6.0.0/bitbucket-rest.html
class Bitbucket(object):
    def __init__(self, module):
        self.module = module
        self.api_token = module.params['api_token']
        self.base_url = module.params['api_url']

    def request(self, url, method='GET', data=None):
        '''
        Sends an API request.  Will take care of serialization of `data` (if
        provided) and desrialization of the response (if possible).

        :arg url: The API endpoint url
        :kwarg method: The HTTP method (default: GET)
        :kwarg data: The request body data, must be serializable to JSON (default:None)
        :returns: A tuple of object (if present in the response) and an error (if one occurred)
        '''
        headers = {}

        if self.api_token:
            headers['Authorization'] = 'Bearer %s' % (self.api_token)

        headers['Accept'] = "application/json"
        headers['Content-Type'] = "application/json"

        response, info = fetch_url(
                module=self.module,
                method=method,
                url='%s%s' % (self.base_url, url),
                headers=headers,
                data=(json.dumps(data) if data else None))

        if info['status'] == 204:
            return None, None
        if info['status'] >= 200 and info['status'] < 300:
            if response:
                return json.loads(response.read()), None
        else:
            error = dict(
                status=info['status'],
            )
            if ('body' in info):
                error.update(dict(body=info['body']))
                try:
                    error.update(dict(decoded=json.loads(info['body'])))
                except:
                    pass
            return None, error

    def request_all(self, url):
        '''
        A generator wrapper around request that handles paging.

        :arg url: The API endpoint url
        :returns: A generator for objects requested at an API endpoint
        '''
        limit = 25
        start = 0

        more = True
        while (more):
            data, error = self.request(
                     '%s%slimit=%d&start=%d' % (url, '&' if '?' in url else '?', limit, start))

            if (error):
                yield None, error

            for i, datum in enumerate(data['values']):
                current = {
                    'current': {
                        'index': i,
                        'value': datum,
                    }
                }
                current.update(data)
                yield current, None

            more = not data['isLastPage']
            if (more):
                start = data['nextPageStart']

def create_webhook(bitbucket, project, repo, webhook):
    return bitbucket.request(
            '/projects/%s/repos/%s/webhooks' % (quote_plus(project), quote_plus(repo)),
            method='POST',
            data=webhook)

def delete_webhook(bitbucket, project, repo, hook_id):
    return bitbucket.request(
            '/projects/%s/repos/%s/webhooks/%d' % (quote_plus(project), quote_plus(repo), hook_id),
            method='DELETE')

def find_webhook(bitbucket, project, repo, name):
    for webhook, error in bitbucket.request_all(
            '/projects/%s/repos/%s/webhooks' % (quote_plus(project), quote_plus(repo))):
        if (error):
            return None, error
        elif (webhook['current']['value']['name'] == name):
            return webhook['current']['value'], None

    return None, None

def update_webhook(bitbucket, project, repo, hook_id, webhook):
    return bitbucket.request(
            '/projects/%s/repos/%s/webhooks/%d' % (quote_plus(project), quote_plus(repo), hook_id),
            method='PUT',
            data=webhook)

def webhook_diff(a, b):
    '''
    Compares two webhooks and returns a list of length 2 containg the
    attributes present in each webhook, not present in the other.

    :arg url: The API endpoint url
    :returns: A generator for objects requested at an API endpoint

    Example::

        existing = {
            "active": true,
            "configuration": {
                "secret": "foobar"
            },
            "createdDate": 1552175029649,
            "events": [
                "repo:refs_changed"
            ],
            "id": 7,
            "name": "five",
            "updatedDate": 1552175029649,
            "url": "http://bitbucket.example.com/asf/fun"
        }

        new_webhook = {
            "configuration": {
                "secret": "foobaz"
            },
            "events": [
                "repo:refs_changed"
            ],
            "name": "five",
            "url": "http://bitbucket.example.com/asf/fun"
        }

        diff = webhook_diff(existing, new_webhook)

        # Results in
        # [
        #     {
        #         "active": true,
        #         "configuration": {
        #             "secret": "foobar"
        #         },
        #         "createdDate": 1552175029649,
        #         "id": 7,
        #         "updatedDate": 1552175029649,
        #     },
        #     {
        #         "configuration": {
        #             "secret": "foobaz"
        #         },
        #     }
        # ]
    '''
    diff = recursive_diff(a, b)
    if ('events' in diff[0] and 'events' in diff[1] and 
            set(diff[0]['events']) == set(diff[1]['events'])):
        del(diff[0]['events'])
        del(diff[1]['events'])
    return diff

def run_module():
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        api_token=dict(type='str', no_log=True),
        force_basic_auth=dict(type='bool', default=False),
        hook_url=dict(type='str', required=True),
        name=dict(type='str', required=True),
        project=dict(type='str', required=True),
        repo=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        token=dict(type='str', no_log=True),
        events=dict(
            type='list',
            default=['repo:refs_changed'],
            choices=[
                'pr:comment:added',
                'pr:comment:edited',
                'pr:comment:deleted',
                'pr:declined',
                'pr:deleted',
                'pr:merged',
                'pr:modified',
                'pr:opened',
                'pr:reviewer:approved',
                'pr:reviewer:needs_work',
                'pr:reviewer:unapproved',
                'pr:reviewer:updated',
                'repo:comment:added',
                'repo:comment:deleted',
                'repo:comment:edited',
                'repo:forked',
                'repo:modified',
                'repo:refs_changed',
            ],
        ),
    ))

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ['api_username', 'api_token'],
            ['api_password', 'api_token']
        ],
        required_together=[
            ['api_username', 'api_password']
        ],
        required_one_of=[
            ['api_username', 'api_token']
        ],
        supports_check_mode=True,
    )

    module.params['url_username'] = module.params['api_username']
    module.params['url_password'] = module.params['api_password']

    state = module.params['state']
    project_identifier = module.params['project']
    repo = module.params['repo']
    name = module.params['name']

    bitbucket = Bitbucket(module)

    existing, error = find_webhook(bitbucket, project_identifier, repo, name)
    if (existing != None):
        module.no_log_values.update([existing['configuration']['secret']])
    result['existing'] = existing

    if (error):
        module.fail_json(**result)
    elif (state == 'absent'):
        if (existing == None):
            result['webhook'] = None
        else:
            if (not module.check_mode):
                result['webhook'], error = delete_webhook(
                        bitbucket,
                        project_identifier,
                        repo,
                        existing['id'])

                if (error):
                    module.fail_json(msg=("Failed: %s" % json.dumps(error)))

            result['changed'] = True
            result['method'] = 'delete'
    else:
        webhook = dict(
            configuration=dict(secret=module.params['token']),
            events=module.params['events'],
            name=name,
            url=module.params['hook_url'],
        )
    
        if (existing == None):
            if (not module.check_mode):
                result['webhook'], error = create_webhook(
                        bitbucket,
                        project_identifier,
                        repo,
                        webhook)

                if (error):
                    module.fail_json(msg=("Failed: %s" % json.dumps(error)))

            result['changed'] = True
            result['method'] = 'create'
        else:
            changes = webhook_diff(existing, webhook)
            if (changes[1]):
                if (not module.check_mode):
                    result['webhook'], error = update_webhook(
                            bitbucket,
                            project_identifier,
                            repo,
                            existing['id'],
                            webhook)

                    if (error):
                        module.fail_json(msg=("Failed: %s" % json.dumps(error)))

                result['changed'] = True
                result['method'] = 'update'
                result['diff'] = changes
            else:
                result['webhook'] = result['existing']

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
