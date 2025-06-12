import json
import yaml
import defusedxml.ElementTree as ET
from xml.etree.ElementTree import Element
import requests
import argparse
from typing import Optional
from getpass import getpass
from dataclasses import dataclass
from pathlib import Path

@dataclass
class User:
    URL: Optional[str] = None
    Debug: bool = False
    CheckOnly: bool = False
    SQLcode: str = ""
    Progressive: bool = False
    Session: requests.Session = requests.Session()

def debugPrint(*objects, sep=' ', startWithNewline=False, end='\n', file=None, flush=False):
    if User.Debug:
        print(f"{"\n" if startWithNewline else ""}\033[90;3m[DEBUG]", *objects, sep=sep, end=(end+"\033[0;0m"), file=file, flush=flush)

typeDict = {
    "user": 0,
    "group": 1,
    "link": 3,
    "email": 4,
    "cloud": 6,
    "circle": 7,
    "talk": 10
}


def fetch_env(envFilename: str) -> tuple[Optional[str], Optional[str]]:
    with open(envFilename) as yamlEnv:
        yamlEnvStruct = yaml.safe_load(yamlEnv)
        User.URL = yamlEnvStruct["server"]
        username = yamlEnvStruct["username"] if 'username' in yamlEnvStruct else None
        password = yamlEnvStruct["password"] if 'password' in yamlEnvStruct else None
    return username, password


def fetch_sharelist() -> list[Element]:
    requestShareUrl = f'{User.URL}/ocs/v2.php/apps/files_sharing/api/v1/shares'

    debugPrint("GET>", requestShareUrl)
    requestShare = User.Session.get(requestShareUrl, headers={"OCS-APIRequest": "true"})

    ocsTree = ET.fromstring(requestShare.text)
    shareList = ocsTree.findall("data/element")
    debugPrint(f"Found {len(shareList)} shares from the user's perspective")

    return shareList

def find_share_by_props(
    shareList: list[Element],
    token: Optional[str] = None,
    share_type: Optional[int] = None,
    uid_owner: Optional[str] = None,
    path: Optional[str] = None,
    shareWith: Optional[str] = None,
    permissions: Optional[int] = None,
    checker: bool = False) -> Optional[Element]:

        arrayOfProps: dict = {}
        if token is not None: arrayOfProps["token"] = token
        if share_type is not None: arrayOfProps["share_type"] = str(share_type)
        if uid_owner is not None: arrayOfProps["uid_owner"] = uid_owner
        if path is not None: arrayOfProps["path"] = path
        if shareWith is not None: arrayOfProps["share_with"] = shareWith
        if permissions is not None: arrayOfProps["permissions"] = str(permissions)

        for item in shareList:
            isValid: bool = True
            for property in arrayOfProps.keys():
                if not (item.find(property) is not None and item.find(property).text == arrayOfProps[property]):
                    if checker: print(f"\n -> '{property}' is WRONG (" + (f"{item.find(property).text} ≠ {arrayOfProps[property]}" if item.find(property) is not None else "missing") + ")", flush=True, end="")
                    isValid = False
                    if not checker: break
                else:
                    if checker: debugPrint(f"'{property}' is OK ({arrayOfProps[property]})", startWithNewline=True, flush=True, end="")
            if isValid:
                return item
        return None

def check_share(share: dict, shareList: list[Element]) -> bool:
    matchingItem: Optional[Element] = find_share_by_props(shareList, token=share["token"])
    if matchingItem is None:
        print("\n -> The token was not found among the shares", flush=True, end="")
        return False

    debugPrint(f"Found matching share with ID = {matchingItem.find("id").text}", startWithNewline=True, flush=True, end="")
    if find_share_by_props([matchingItem], share_type=typeDict[share["type"]], uid_owner=share["owner"], path=share["path"], shareWith=(share["recipient"] if share["type"] == 'email' else None), permissions=share["permissions"], checker=True) is not None:
        return True

    return False


def create_share(path: str, plainType: str, shareWith: Optional[str], permissions: int, token: Optional[str], shareListIfTokenOnly: Optional[list[Element]] = None) -> tuple[bool, bool]: # Returns (isCreated, isTokenFixed)

    createShareReq: Optional[requests.Response] = None

    if not shareListIfTokenOnly:
        createShareUrl = f'{User.URL}/ocs/v2.php/apps/files_sharing/api/v1/shares'

        postArgs = {
            'path': path,
            'shareType': typeDict[plainType],
            'shareWith': shareWith,
            'permissions': permissions,
            'sendMail': "false" if plainType == "email" else None
        }

        debugPrint("POST>", createShareUrl, postArgs)
        createShareReq = User.Session.post(createShareUrl, json=postArgs, headers={"OCS-APIRequest": "true"})


        match createShareReq.status_code:
            case 200:
                print("\033[32;1mOK!\033[0;0m")
            case _:
                debugPrint(createShareReq.status_code, f"\n{createShareReq.text}")
                print("\033[31;1mFAIL!\033[0;0m")
                return False, False

    if token is not None:

        tree: Optional[Element[str]] = None
        if shareListIfTokenOnly:
            debugPrint(f"Finding shares with the following properties: path={path}, share_type={typeDict[plainType]}, shareWith={shareWith}, permissions={permissions}")
            foundShare = find_share_by_props(shareListIfTokenOnly, path=path, share_type=typeDict[plainType], shareWith=shareWith, permissions=permissions)
            if foundShare is not None:
                tree = foundShare
            else:
                print("\033[31;1mNOT FOUND\033[0;0m")
                return True, False
        elif createShareReq:
            tree = ET.fromstring(createShareReq.text)

        assert type(tree) is Element

        nodeFind = tree.find("data/id")
        if nodeFind is None: nodeFind = tree.find("id")

        assert nodeFind is not None

        shareID = nodeFind.text

        debugPrint(f"Share ID detected: {shareID}")

        if plainType == "link":
            print(" -> Applying custom token for the shared link...", flush=True, end=("\n" if User.Debug else ""))

            customTokenURL = f'{User.URL}/ocs/v2.php/apps/files_sharing/api/v1/shares/{shareID}'

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

            debugPrint("PUT>", customTokenURL, customTokenArgs)
            editTokenReq = User.Session.put(customTokenURL, json=customTokenArgs, headers={"OCS-APIRequest": "true"})


            match editTokenReq.status_code:
                case 200:
                    print("\033[32;1mOK!\033[0;0m")
                case _:
                    debugPrint(editTokenReq.status_code, f"\n{editTokenReq.text}")
                    print("\033[31;1mFAIL!\033[0;0m")
                    return True, False

        elif plainType == "email":
            print(" -> Crafting a database command for the shared link...", flush=True, end=("\n" if User.Debug else ""))
            appendedCommand: str = f"UPDATE public.oc_share SET token = '{token}' WHERE id = {shareID}"
            debugPrint("SQL Request:", appendedCommand)
            User.SQLcode += appendedCommand + ";\n"
            print("\033[32;1mOK!\033[0;0m")

    return True, True


def main():
    parser = argparse.ArgumentParser(
                        prog='Nextcloud Shares Migrator',
                        description='Easily recreate shares from a sharing:list json output to a new server thanks to the OCS Share API',
                        epilog='Made with <3 by DodoLeDev')
    parser.add_argument('filename')
    parser.add_argument('-e', '--env', help='Provide an env file for keeping secrets')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Toggles verbose mode')
    parser.add_argument('-p', '--progressive',
                        action='store_true', help='Make the migration completely interactive. The user needs to confirm before migrating each share (useless with --check)')
    parser.add_argument('-d', '--dry-run',
                        action='store_true', help='Display requests without sending them')
    parser.add_argument('-c', '--check',
                        action='store_true', help='Check wheither the shares are correctly created (implies --dry-run)')
    parser.add_argument('-f', '--fix',
                        action='store_true', help='Creates a copy of the list of shares containing only the shares that have not been verified nor successfully created')
    parser.add_argument('-s', '--server',
                        help='URL of the nextcloud server')
    parser.add_argument('-U', '--username',
                        help='Username for logging-in through the nextcloud server')
    parser.add_argument('-P', '--password',
                        help='Password for logging-in through the nextcloud server')

    args = parser.parse_args()
    username = None
    password = None
    fixed_file_path: Optional[Path] = None

    if not args.env:
        if not (args.server):
            print("Error: You must provide a server URL or an env file")
            return
        User.URL = args.server
    else:
        username, password = fetch_env(args.env)

    User.Debug = args.verbose
    User.CheckOnly = args.check
    User.Progressive = args.progressive

    debugPrint("Defining a non-overlapping filename for the SQL code...")
    orig_filepath = Path(args.filename)
    sql_file_path = Path(f"{orig_filepath.stem}_sqlcode.sql")
    filenameIndex: int = 0
    while sql_file_path.exists():
        filenameIndex += 1
        sql_file_path = Path(f"{orig_filepath.stem}_sqlcode-{filenameIndex}.sql")
    debugPrint(f"This filename is not taken: {sql_file_path}. Using it..")

    if args.fix:
        debugPrint("Defining a non-overlapping filename for the fixed share list...")
        fixed_file_path = Path(f"{orig_filepath.stem}_fixed{orig_filepath.suffix}")
        filenameIndex = 0
        while fixed_file_path.exists():
            filenameIndex += 1
            fixed_file_path = Path(f"{orig_filepath.stem}_fixed-{filenameIndex}{orig_filepath.suffix}")
        debugPrint(f"This filename is not taken: {fixed_file_path}. Using it..")

    if not username: username = args.username if args.username is not None else input("Username: ")
    if not password: password = args.password if args.password is not None else getpass("Password: ")

    assert password
    assert username

    # Check if credentials are correct
    url = f'{User.URL}/ocs/v1.php/cloud/users/{username}'

    User.Session.auth = (username, password)

    debugPrint("GET>", url)
    credsTest = User.Session.get(url, headers={"OCS-APIRequest": "true"})

    if credsTest.status_code != 200: raise Exception("Credentials are incorrect")

    with open(args.filename) as shareDictFile:
        shareDict = json.load(shareDictFile)

    failedList: list[dict] = []
    shareList = fetch_sharelist()
    if User.CheckOnly:
        for share in shareDict:
            if "token" in share:
                print(f"\033[1m>>> Checking publicly shared file '{share["path"]}'{f" (with token '{share["token"]}')" if User.Debug else ""}...\033[0m", flush=True, end="")
                if check_share(share, shareList):
                    print(f"\033[32;1m{"\n  > " if User.Debug else ""}OK!\033[0;0m{"\n" if User.Debug else ""}")
                else:
                    print("\n  \033[31;1m> FAIL!\033[0;0m\n")
                    failedList.append(share)
            else:
                debugPrint(f"Skipping shared file '{share["path"]}' as it is not publicly accessible (does not have a token)")
                failedList.append(share)
    else:
        skipNext: bool = False
        for share in shareDict:
            if skipNext:
                debugPrint(f"Skipping shared file '{share["path"]}' because migration has been aborted")
                failedList.append(share)
            elif share["initiator"] == username:

                if User.Progressive:
                    shouldIcontinue: str = input(f" -> You are going to migrate the file '{share["path"]}'. Continue? [Yes/no/abort] ")
                    if shouldIcontinue == "": shouldIcontinue = "Y"
                    match shouldIcontinue.lower()[0]:
                        case 'n':
                            continue
                        case 'a':
                            skipNext = True
                            continue


                print(f"\033[1m>>> Migrating shared file '{share["path"]}' in {share["type"]} mode...\033[0m", flush=True, end=("\n" if User.Debug else ""))
                debugPrint(f"Properties: path={share["path"]} ; plainType={share["type"]}, shareWith={share["recipient"] if "recipient" in share else "<not provided>"}, permissions={share["permissions"]}, token={share["token"] if "token" in share else "<not provided>"}")
                creationStatus: bool = False
                tokenStatus: bool = False

                try:
                    creationStatus, tokenStatus = create_share(share["path"], share["type"], share["recipient"] if share["type"] != "link" else None, share["permissions"], share["token"] if share["type"] in ["link", "email"] else None, shareList if "tokenOnly" in share and share["tokenOnly"] else None)
                except Exception as e:
                    print(f"\033[31;1m[ERROR] {e}\033[0;0m")
                    continueAfterError: str = input("        Continue anyway? [Y/n] ")
                    if len(continueAfterError) > 0 and continueAfterError.lower()[0] == "n": skipNext = True

                if not creationStatus:
                    failedList.append(share)
                elif creationStatus and not tokenStatus:
                    share["tokenOnly"] = True
                    failedList.append(share)

            else:
                debugPrint(f"Skipping shared file '{share["path"]}' as it is not initiated by logged in user ({share["initiator"]})")
                failedList.append(share)

        if User.SQLcode != "":
            print("\n\033[1;33m⚠ \033]8;;https://github.com/nextcloud/server/issues/53442\033\\As of now, Nextcloud does not allow to customize tokens for email shares\033]8;;\033\\ (while still being a link share after all!)\033[0;0m")
            with open(sql_file_path, "w") as s:
                s.write(User.SQLcode)
                s.write("COMMIT;")
                print(f"\033[1m[i] The list of SQL code to apply custom tokens for e-mail shares has been saved in file {sql_file_path}\033[0m")


    if fixed_file_path:
        if len(failedList) > 0:
            with open(fixed_file_path, "w") as f:
                json.dump(failedList, f, indent=2)
                print(f"\033[1m[i] The list of unsuccessful shares has been saved in file {fixed_file_path}\033[0m")
        else:
            print("\033[1mNo share is missing nor failed, so no fixed file have been created\033[0m")

main()
