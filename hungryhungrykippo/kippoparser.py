#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
import json
from collections import deque
from kippo_object import LoginAttempt


class KippoParser(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def write_kippo_json_to_file(self, log_path, output_path):
        '''
        Parse kippo log into JSON and output to a file

        :param log_path:
        :param output_path:
        :return: N/A
        '''

        with open(output_path, 'w') as output_file:
            json_logs = self.parse_log_file_to_json_kippo_objects(log_path)
            output_file.write(json_logs)

    def parse_log_file_to_json_kippo_objects(self, log_path):
        '''
        Parse a log file into JSON Kippo Objects

        :param log_path:
        :return: JSON string
        '''
        logging.info('Creating JSON kippo objects for {}'.format(log_path))
        kippo_objects = self.parse_log_file_to_kippo_objects(log_path)
        kippo_objects = map(lambda x: x.__dict__, kippo_objects)
        kippo_json_string = json.dumps(kippo_objects)
        logging.info('Successfully generated Kippo JSON string')
        return kippo_json_string

    def parse_log_file_to_kippo_objects(self, log_path):
        '''
        Translate a kippo log file into kippo objects

        :param log_path:
        :return: Kippo objects
        '''

        logging.info('Translating {} into kippo objects'.format(log_path))

        models = deque()

        with open(log_path) as log_file:
            log_entries = self._split_log_into_list_of_entries(log_file)

            for log_entry in log_entries:
                attempt = LoginAttempt()
                credentials = self._extract_credentials_from(log_entry)
                timestamp = self._extract_timestamp_from(log_entry)
                ip_address = self._extract_ip_address_from(log_entry)
                if not credentials or not timestamp or not ip_address:
                    continue
                attempt.intrusion_username = credentials['username']
                attempt.intrusion_password = credentials['password']
                attempt.intrusion_originating_ip = ip_address
                attempt.intrusion_date = timestamp['date']
                attempt.intrusion_time = timestamp['time']
                attempt.intrusion_timezone = timestamp['timezone']
                models.append(attempt)

            logging.info('Generated {} kippo objects'.format(len(models)))
            return models

    def _split_log_into_list_of_entries(self, log_file):
        '''
        Split a log file into a list of log event entries

        :param log_file:
        :return: A list of individual log entries
        '''
        log_file = log_file.read()
        log_entries = log_file.split('[-] New connection: ')
        if not log_entries:
            raise ValueError("This file does not appear to be a valid kippo log file")
        return log_entries

    def _extract_credentials_from(self, log_entry):
        '''
        Extract a credential pair from a log entry

        :param log_entry:
        :return: Credentials dictionary or None
        '''
        credentials_regex = re.compile("login attempt \[[^\[\]]*\]")
        credential_hit = re.search(credentials_regex, log_entry)
        # Removes the string 'login attempt [' and the last character of the string, then splits it once on the / char
        if credential_hit:
            credential_hit = credential_hit.group()
            credential_hit = credential_hit.replace('login attempt [', '')[:-1].split('/', 1)
            credentials = {'username': credential_hit[0], 'password': credential_hit[1]}
            return credentials
        else:
            return None

    def _extract_timestamp_from(self, log_entry):
        '''
        Extract timestamp from a log entry

        :param log_entry:
        :return: Parsed timestamp
        '''
        timestamp_regex = re.compile("\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\+\d{4}")
        timestamp = re.search(timestamp_regex, log_entry)
        if timestamp:
            timestamp = timestamp.group()
            timezone = timestamp.split('+', 1)[-1] # Split on the + symbol and grab the last item in the array
            date = timestamp[:-5].split(' ')[0]
            time = timestamp[:-5].split(' ')[1]
            parsed_timestamp = {'date': date, 'time': time, 'timezone': timezone}
            return parsed_timestamp
        else:
            return None

    def _extract_ip_address_from(self, log_entry):
        '''
        Extract an IP address from a log entry

        :param log_entry: An entry block from the kippo log
        :return: An IP address or a None value
        '''
        ip_regex = re.compile("^\d*\..\d*\.\d*\.\d*")
        ip_matches = ip_regex.match(log_entry)
        if ip_matches:
            return ip_matches.group()
        else:
            return None