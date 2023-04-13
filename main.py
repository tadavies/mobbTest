import argparse
import json
import os
import re
import urllib.request, urllib.error
from urllib.parse import urlparse


def parse_arguments():
    parser = argparse.ArgumentParser(description='Check if a Snyk Code report is for a specific GitHub repository and commit.')
    parser.add_argument('repo_url', type=str, help='GitHub repository URL')
    parser.add_argument('commit_hash', type=str, help='git commit hash')
    parser.add_argument('report_path', type=str, help='path to Snyk Code report')
    return parser.parse_args()
   
class SnykParser:
    def __init__(self, owner: str, repo: str, report_path: str, commit_hash: str):
        self.owner = owner
        self.repo = repo
        self.report_path = report_path
        self.commit_hash = commit_hash
        self.file_store = {}
        self.error_message = None

    def is_valid(self) -> bool:
        with open(self.report_path, 'r', encoding="utf-8") as f:
            report = json.load(f)
        runs = report.get('runs')
        for run in runs:
            results = run.get('results')
            for result in results:
                # Get base location data
                for location in result.get('locations'):
                    try:
                        location_data = self.get_location_data(location)
                        # print(f"{result['ruleId']} - {location_data}\n")
                    except Exception as e:
                        self.error_message = e
                        return False

                # Get code flow data
                code_flow_dict = {}
                for code_flow in result.get('codeFlows'):
                    for thread_flow in code_flow.get('threadFlows'):
                        for location in thread_flow.get('locations'):
                            location = location['location']
                            try:
                                location_data = self.get_location_data(location)
                                code_flow_dict[location['id']] = location_data
                            except Exception as e:
                                self.error_message = e
                                return False
        return True

    # Given a Snyk location object return the location code as a string
    def get_location_data(self, location: dict) -> str:
        uri = location.get('physicalLocation').get('artifactLocation').get('uri')
        
        # Check we havent already downloaded the raw code from git
        if uri not in self.file_store:
            # Get raw code from git
            rawLines = self.get_git_raw(uri)
            self.file_store[uri] = rawLines 
  
 
        region = location.get('physicalLocation').get('region')
        location_data = self.get_region_text(uri, region)
        return location_data

    # Get githib content
    def get_git_raw(self, uri_path: str) -> list:
        url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.commit_hash}/{uri_path}"
        try:
            conn = urllib.request.urlopen(url)
        except urllib.error.HTTPError as e:
            raise Exception('HTTPError: {}'.format(e.code))
        data = conn.read()
        if data == None:
            raise Exception('Error getting data from github')
        return data.splitlines()


    # Given a snyk region object and the corresponding code return the given region text
    def get_region_text(self, uri: str, region: str) -> str:
        raw_lines = self.file_store[uri]
        # Bounds check on line number, linenumber is not zero based hence - 1
        if region['endLine']-1 > len(raw_lines):
            raise Exception(f'BoundsCheck - LineNumber')
        
        # Get lines from list to match snyk report
        if region['startLine'] == region['endLine']:
            line = raw_lines[region['startLine']-1]

            # Convert to utf-8 and expand tabs for column slice
            line = line.decode("utf-8").expandtabs(1)

            # Bounds check on column, pos is not zero based hence -1
            if len(line) < region['endColumn']-1:
                raise Exception(f'BoundsCheck - ColumnPos')

            line = line[region['startColumn']-1:region['endColumn']-1]

        # Handle multi-line regions
        else:
            lines = []
            for line in raw_lines[region['startLine']-1:region['endLine']]:
                lines.append(line.decode("utf-8").expandtabs(1))
           
            # Bounds check on column, pos is not zero based hence -1
            if len(lines[0]) < region['startColumn']-1:
                raise Exception(f'BoundsCheck - ColumnPos')
            if len(lines[-1]) < region['endColumn']-1:
                raise Exception(f'BoundsCheck - ColumnPos')

            lines[0] = lines[0][region['startColumn']-1:]
            lines[-1] = lines[-1][:region['endColumn']-1].lstrip()
            line = ''.join(lines)
        return line

if __name__ == '__main__':
    args = parse_arguments()

    if not os.path.exists(args.report_path):
        raise ValueError('Snyk Code report path does not exist.')

    if not args.repo_url.startswith('https://github.com/'):
        raise ValueError('Invalid GitHub repository URL.')

    if not re.match(r'[a-fA-F0-9]{40}$', args.commit_hash):
        raise ValueError('Invalid git commit hash.', args.commit_hash)

    # Split git hub url into owner and repo
    owner, repo = urlparse(args.repo_url).path.split('/')[1:]

    # Init snyk parser clasee
    snyk_parser = SnykParser(owner, repo, args.report_path, args.commit_hash)
  
    if snyk_parser.is_valid():
        print('true')
    else:
        print('false')