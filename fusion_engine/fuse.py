import argparse
import shutil
import glob
from consts import *
from manifest import get_application_name_and_package
from smali import patch_smali_file


def place_agent_so(apk_dir: Path, target_abi: str, agent_so: Path):
    target_dir = apk_dir / LIB_DIR_NAME / target_abi
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(agent_so, target_dir / agent_so.name)


def get_smali_file(apk_dir: Path, class_name: str, package: str = '') -> Path:
    # Try without package
    app_path = str(apk_dir / (SMALI_DIR_NAME + '*') / Path(*class_name.split('.'))) + SMALI_EXTENSION
    smali_files = glob.glob(app_path)
    if not smali_files:
        # Try with package
        class_name = '.'.join((package, class_name))
        app_path = str(apk_dir / (SMALI_DIR_NAME + '*') / Path(*class_name.split('.'))) + SMALI_EXTENSION
        smali_files = glob.glob(app_path)
        if not smali_files:
            # Return path to new file
            return str(apk_dir / SMALI_DIR_NAME / Path(*class_name.split('.'))) + SMALI_EXTENSION
    return Path(smali_files[0])


def build_parser(parser: argparse.ArgumentParser = None) -> argparse.ArgumentParser:
    parser = parser or argparse.ArgumentParser()
    parser.add_argument('apk_dir', type=Path)
    parser.add_argument('agent_so', type=Path)
    return parser


def main(args: argparse.Namespace):
    target_abi = args.agent_so.parent.name
    agent_name = SO_NAME_REGEX.match(args.agent_so.name).group(1)
    manifest_path = args.apk_dir / MANIFEST_FILE_NAME
    app_name, package = get_application_name_and_package(str(manifest_path), default_app_name=DEFAULT_APP_NAME)
    smali_file = get_smali_file(args.apk_dir, app_name, package=package)
    patch_smali_file(smali_file, agent_name, args.apk_dir)
    place_agent_so(args.apk_dir, target_abi, args.agent_so)


if __name__ == '__main__':
    main(build_parser().parse_args())
