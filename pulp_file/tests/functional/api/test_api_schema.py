# coding=utf-8
"""Assert that there is no changes in autogenerated API."""
import json
import os
import subprocess
import tempfile
import unittest

from pulp_smash import api, config
from pulp_file.tests.functional.constants import API_SCHEMA_PATH
from pulp_file.tests.functional.utils import set_up_module as setUpModule  # noqa:F401


class APISchemaTestCase(unittest.TestCase):
    """Verify API schema change.

    This test targets the following issue:

    * `Pulp #4123 <https://pulp.plan.io/issues/4123>`_
    """

    def test_verify_api_schema(self):
        """Verify API schema change."""
        client = api.Client(config.get_config(), api.json_handler)
        generated_open_api = client.get(API_SCHEMA_PATH)

        current_dir = os.path.dirname(os.path.abspath(__file__))
        assets_dir = os.path.join(current_dir, 'assets')

        with tempfile.TemporaryDirectory() as temp_dir:
            generated_open_api_path = os.path.join(
                temp_dir,
                'generated_open_api.json'
            )
            create_json(generated_open_api_path, generated_open_api)
            stored_open_api_path = os.path.join(
                assets_dir,
                'stored_open_api.json'
            )
            stored_open_api = load_json(stored_open_api_path)
            current_schema_path = os.path.join(
                temp_dir,
                'current_stored_open_api.json'
            )
            create_json(current_schema_path, stored_open_api)
            cmd = 'diff -u -b  {} {}'.format(
                current_schema_path,
                generated_open_api_path
            )
            diff = subprocess.run(cmd.split(), stdout=subprocess.PIPE).stdout
            self.assertEqual(len(diff), 0, diff)


def load_json(json_path):
    """Load a json file from the filesystem."""
    with open(json_path, 'r') as json_file:
        data = json.load(json_file)
    return data


def create_json(json_path, json_data):
    """Create a json file given a path."""
    # Remove `host` element from the json file since this element will change.
    # when running the test in different hosts.
    json_data.pop('host', None)
    with open(json_path, 'w') as data_file:
        json.dump(json_data, data_file, sort_keys=True, indent=2)
