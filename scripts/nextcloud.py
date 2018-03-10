#!/usr/bin/python2
""" Takes nextcloud settings as yaml an sets them accordingly with php occ """
from subprocess import call
import argparse
import yaml


def get_type_php_from_object(value):
    """ Return php type name of type of value """
    if isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "float"
    return "string"


def generate_paths(data):
    """ Return list of lists containing the required values to pass to call """
    execute_list = []
    if not isinstance(data, (list, dict)):
        return data
    if isinstance(data, dict):
        for key, value in data.iteritems():
            if isinstance(value, (list, dict)):
                paths = generate_paths(value)
                for path in paths:
                    path.insert(0, key)
                    execute_list.append(path)
            else:
                execute_list.append([key, value])
    elif isinstance(data, list):
        for num, value in enumerate(data):
            if isinstance(value, (list, dict)):
                paths = generate_paths(value)
                for path in paths:
                    path.insert(0, str(num))
                    execute_list.append(path)
            else:
                execute_list.append([str(num), value])
    return execute_list


PARSER = argparse.ArgumentParser(description='This script converts a yaml\
        input object to commands to configure nextcloud and executes them.')
PARSER.add_argument('yaml_file_path', metavar='YAML', type=str,
                    help='Path to yaml file to be proccsed')
ARGS = PARSER.parse_args()
with open(ARGS.yaml_file_path, 'r') as yaml_file:
    YAML_STRING = yaml_file.read()
    COMMANDS = generate_paths(yaml.load(YAML_STRING))
    USER = "www-data"
    for command in COMMANDS:
        region = 'app' if command[0] == 'apps' else 'system'
        value_to_set = command[-1]
        value_type = get_type_php_from_object(value_to_set)
        plain = ['sudo',
                 '-u',
                 USER,
                 'php',
                 'occ',
                 'config:{0}:set'.format(region),
                 '--value={0}'.format(value_to_set),
                 '--type={0}'.format(value_type)]
        plain[6:6] = command[1:-1]
        plain = plain if command[0] == "system" else plain[:-1]
        call(plain)
