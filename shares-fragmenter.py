import json
import argparse
from pathlib import Path

debugEnabled: bool = False

def debugPrint(*objects, sep=' ', startWithNewline=False, end='\n', file=None, flush=False):
    if debugEnabled:
        print(f"{"\n" if startWithNewline else ""}\033[90;3m[DEBUG]", *objects, sep=sep, end=(end+"\033[0;0m"), file=file, flush=flush)

def get_nonoverlapping_file(initialFilename: str) -> Path:
    debugPrint("Defining a non-overlapping filename...")
    original_fileObj = Path(initialFilename)
    unused_fileObj = Path(initialFilename)
    filenameIndex: int = 0
    while unused_fileObj.exists():
        filenameIndex += 1
        unused_fileObj = Path(f"{original_fileObj.stem}({filenameIndex}).{original_fileObj.suffix}")
    debugPrint(f"This filename is not taken: {unused_fileObj}. Using it..")
    return unused_fileObj

def main():
    parser = argparse.ArgumentParser(
                        prog='Shares Fragmenter',
                        description='Helps you to fragment the file containing all the shares on a per-user basis',
                        epilog='Made with <3 by DodoLeDev')
    parser.add_argument('filename')
    parser.add_argument('output_pattern')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Toggles verbose mode')
    parser.add_argument('-d', '--dry-run',
                        action='store_true', help='Display requests without sending them')

    args = parser.parse_args()

    global debugEnabled
    debugEnabled = args.verbose
    filenamePattern: str = args.output_pattern

    if "%username%" not in filenamePattern:
        print("[NOTE] '%username%' not found in output_pattern. The username will be appended at the end of the filename")
        if '.' in filenamePattern:
            splittedFilename: list = filenamePattern.rsplit('.', 1)
            filenamePattern = "-%username%.".join(splittedFilename)
        else:
            filenamePattern += "-%username%"
        debugPrint(f"The following new pattern will be applied: {filenamePattern}")

    # Open the shares file
    debugPrint(f"Opening file {args.filename}...")
    with open(args.filename) as shareDictFile:
        shareDict = json.load(shareDictFile)

    print(f"{len(shareDict)} shares have been found")

    # Parses the output per-user
    userSharesDict: dict[str,list] = {}


    for share in shareDict:
        debugPrint(f"Share initiated by {share["initiator"]} has been discovered ({share["path"]})")
        if share["initiator"] not in userSharesDict:
            userSharesDict[share["initiator"]] = []
        userSharesDict[share["initiator"]].append(share)

    userFileObj: Path
    print("\033[1m<== Statistics ==>\033[0m")
    for user in userSharesDict.keys():
        print(f"> \033[36m{user}\033[0m: {len(userSharesDict[user])} shares")

        userFileObj = get_nonoverlapping_file(filenamePattern.replace('%username%', user))
        with open(userFileObj, "w") as f:
            json.dump(userSharesDict[user], f, indent=2)
            debugPrint("Shares saved!")

main()
