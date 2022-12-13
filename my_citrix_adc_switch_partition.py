#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 Citrix Systems, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: my_citrix_adc_switch_partition
short_description: switch Citrix ADC partitions
description:
    - switch Citrix ADC partitions

version_added: "1.0.0"

author:
    - Piotr Kodzis; reworked original citrix_adc_nspartition module

options:

    partitionname:
        description:
            - >-
                Name of the Partition. Must begin with an ASCII alphanumeric or underscore (_) character, and must
                only ASCII alphanumeric, underscore, hash (#), period (.), space, colon (:), at (@), equals (=), and
                (-) characters.
            - "Minimum length =  1"
        type: str

'''

EXAMPLES = '''
- name: switch partition
  delegate_to: localhost
  my_citrix_adc_switch_partition:
    nsip: 10.74.22.22
    nitro_auth_token: "{{nitro_auth_token}}"
    partitionname: par1
'''

RETURN = '''
loglines:
    description: list of logged messages by the module
    returned: always
    type: list
    sample: ['message 1', 'message 2']

msg:
    description: Message detailing the failure reason
    returned: failure
    type: str
    sample: "Action does not exist"

diff:
    description: List of differences between the actual configured object and the configuration specified in the module
    returned: failure
    type: dict
    sample: { 'clttimeout': 'difference. ours: (float) 10.0 other: (float) 20.0' }
'''

import base64
import codecs
import copy
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.citrix.adc.plugins.module_utils.citrix_adc import (
    NitroResourceConfig,
    NitroException,
    netscaler_common_arguments,
    log,
    loglines,
    NitroAPIFetcher
)


class ModuleExecutor(object):

    def __init__(self, module):
        self.module = module
        self.fetcher = NitroAPIFetcher(self.module)

        # Dictionary containing attribute information
        # for each NITRO object utilized by this module
        self.attribute_config = {
            'nspartition': {
                'attributes_list': [
                    'partitionname',
                ],
                'transforms': {
                },
                'get_id_attributes': [
                    'partitionname',
                ],
                'delete_id_attributes': [
                ],
                'non_updateable_attributes': [
                ],
            },
        }

        self.module_result = dict(
            changed=False,
            failed=False,
            loglines=loglines,
        )

        # Calculate functions will apply transforms to values read from playbook
        self.calculate_configured_nspartition()

    def calculate_configured_nspartition(self):
        log('ModuleExecutor.calculate_configured_nspartition()')
        self.configured_nspartition = {}
        for attribute in self.attribute_config['nspartition']['attributes_list']:
            value = self.module.params.get(attribute)
            # Skip null values
            if value is None:
                continue
            transform = self.attribute_config['nspartition']['transforms'].get(attribute)
            if transform is not None:
                value = transform(value)
            self.configured_nspartition[attribute] = value

        log('calculated configured nspartition %s' % self.configured_nspartition)

    def switch_partition(self):
        log('ModuleExecutor.switch_partition')

        post_data = {
            'nspartition':{
                'partitionname': self.module.params['partitionname'],
            }
        }

        result = self.fetcher.post(post_data=post_data, resource='nspartition', action='Switch')

        if result['http_response_data']['status'] != 200:
            msg = 'Switch partition operation failed'
            self.module.fail_json(msg=msg, **self.module_result)

        self.module_result['switch_partition_result'] = result['http_response_data']

    def main(self):
        try:

            self.switch_partition()

            self.module.exit_json(**self.module_result)

        except NitroException as e:
            msg = "nitro exception errorcode=%s, message=%s, severity=%s" % (str(e.errorcode), e.message, e.severity)
            self.module.fail_json(msg=msg, **self.module_result)
        except Exception as e:
            msg = 'Exception %s: %s' % (type(e), str(e))
            self.module.fail_json(msg=msg, **self.module_result)


def main():

    argument_spec = dict()

    module_specific_arguments = dict(
        partitionname=dict(type='str'),
    )

    argument_spec.update(netscaler_common_arguments)
    argument_spec.update(module_specific_arguments)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    executor = ModuleExecutor(module=module)
    executor.main()


if __name__ == '__main__':
    main()
