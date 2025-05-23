import json
import yaml
import defusedxml.ElementTree as ET
import requests
import argparse
from typing import Optional
from getpass import getpass
from dataclasses import dataclass

@dataclass
class User:
    URL: Optional[str] = None
    Username: Optional[str] = None
    Password: Optional[str] = None
    Debug: bool = False

def debugPrint(*args, **kwargs):
    if User.Debug:
        print("[DEBUG]", *args, **kwargs)



def fetch_env(envFilename: str):
    with open(envFilename) as yamlEnv:
        yamlEnvStruct = yaml.safe_load(yamlEnv)
        globalUser.URL = yamlEnvStruct["server"]
        globalUser.Username = yamlEnvStruct["username"] if 'username' in yamlEnvStruct else None
        globalUser.Password = yamlEnvStruct["password"] if 'password' in yamlEnvStruct else None
    return


def create_share(path: str, plainType: str, shareWith: Optional[str], permissions: int, token: Optional[str]):
    assert globalUser.Password
    assert globalUser.Username

    typeDict = {
        "user": 0,
        "group": 1,
        "link": 3,
        "email": 4,
        "cloud": 6,
        "circle": 7,
        "talk": 10
    }

    createShareUrl = f'{globalUser.URL}/ocs/v2.php/apps/files_sharing/api/v1/shares'

    postArgs = {
        'path': path,
        'shareType': typeDict[plainType],
        'shareWith': shareWith,
        'permissions': permissions,
        'sendMail': "false" if plainType == "email" else None
    }

    debugPrint(createShareUrl, postArgs)

    createShareReq = requests.post(createShareUrl, json=postArgs, headers={"OCS-APIRequest": "true"}, auth=(globalUser.Username, globalUser.Password))

    match createShareReq.status_code:
        case 200:
            print("\033[32;1mOK!\033[0;0m")
        case _:
            print("\033[31;1mFAIL!\033[0;0m")


    debugPrint(createShareReq.text)

    if (plainType == "link" or plainType == "email") and token is not None:
        print(" -> Applying custom token for the shared link...", flush=True, end=("" if globalUser.Debug else "\n"))

        tree = ET.fromstring(createShareReq.text)
        shareID = tree.find("data/id").text

        debugPrint(f"Share ID detected: {shareID}")

        customTokenURL = f'{globalUser.URL}/ocs/v2.php/apps/files_sharing/api/v1/shares/{shareID}'

        customTokenArgs = {
            "permissions": permissions,
            "attributes":"[]",
            "note":"",
            "expireDate":"",
            "label":"",
            "password":"",
            "hideDownload":"false",
            "token": token
        }

        editTokenReq = requests.put(customTokenURL, json=customTokenArgs, headers={"OCS-APIRequest": "true"}, auth=(globalUser.Username, globalUser.Password))

        match createShareReq.status_code:
            case 200:
                print("\033[32;1mOK!\033[0;0m")
            case _:
                print("\033[31;1mFAIL!\033[0;0m")

        debugPrint(editTokenReq.text)

    return


def main():
    parser = argparse.ArgumentParser(
                        prog='Nextcloud Shares Migrator',
                        description='Easily recreate shares from a sharing:list json output to a new server thanks to the OCS Share API',
                        epilog='Made with <3 by DodoLeDev')
    parser.add_argument('filename')
    parser.add_argument('-e', '--env', help='Provide an env file for keeping secrets')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Toggles verbose mode')
    parser.add_argument('-d', '--dry-run',
                        action='store_true', help='Display requests without sending them')
    parser.add_argument('-s', '--server',
                        help='URL of the nextcloud server')
    parser.add_argument('-U', '--username',
                        help='Username for logging-in through the nextcloud server')
    parser.add_argument('-P', '--password',
                        help='Password for logging-in through the nextcloud server')

    args = parser.parse_args()

    if not args.env:
        if not (args.server):
            print("Error: You must provide a server URL or an env file")
            return
        globalUser.URL = args.server
    else:
        fetch_env(args.env)

    User.Debug = args.verbose
    if not globalUser.Username: globalUser.Username = args.username if args.username is not None else input("Username: ")
    if not globalUser.Password: globalUser.Password = args.password if args.password is not None else getpass("Password: ")

    assert globalUser.Password
    assert globalUser.Username

    # Check if credentials are correct
    url = f'{globalUser.URL}/ocs/v1.php/cloud/users/{globalUser.Username}'

    credsTest = requests.get(url, headers={"OCS-APIRequest": "true"}, auth=(globalUser.Username, globalUser.Password))

    if credsTest.status_code != 200: raise Exception("Credentials are incorrect")

    with open(args.filename) as shareDictFile:
        shareDict = json.load(shareDictFile)

    for share in shareDict:
        if share["initiator"] == globalUser.Username:
            print(f">>> Migrating shared file '{share["path"]}' in {share["type"]} mode...", flush=True, end=("" if globalUser.Debug else "\n"))
            debugPrint(f"Properties: path={share["path"]} ; plainType={share["type"]}, shareWith={share["recipient"] if "recipient" in share else "<not provided>"}, permissions={share["permissions"]}, token={share["token"] if "token" in share else "<not provided>"}")
            create_share(share["path"], share["type"], share["recipient"] if share["type"] != "link" else None, share["permissions"], share["token"] if share["type"] == "link" else None)
        else:
            debugPrint(f"Skipping shared file '{share["path"]}' as it is not initiated by logged in user ({share["initiator"]})")


globalUser = User()
main()
