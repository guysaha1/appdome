import re
from pathlib import Path

MANIFEST_FILE_NAME = Path('AndroidManifest.xml')
SMALI_DIR_NAME = 'smali'
SMALI_EXTENSION = '.smali'
LIB_DIR_NAME = 'lib'

SO_NAME_REGEX = re.compile(r'lib(.+)\.so')

DEFAULT_APP_NAME = 'app'
