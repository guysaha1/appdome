from lxml import etree
from typing import Tuple

PACKAGE_TAG = 'package'
APPLICATION_TAG = 'application'
APPLICATION_NAME_ATTRIBUTE = '{http://schemas.android.com/apk/res/android}name'


def get_application_name_and_package(manifest_path: str, default_app_name: str = '') -> Tuple[str, str]:
    parsed_manifest = etree.parse(manifest_path)
    root = parsed_manifest.getroot()
    app_tag = root.find(APPLICATION_TAG)
    if app_tag is not None:
        app_name = app_tag.get(APPLICATION_NAME_ATTRIBUTE)
        if not app_name:
            app_name = default_app_name
            app_tag.set(APPLICATION_NAME_ATTRIBUTE, app_name)
            parsed_manifest.write(manifest_path)
    else:
        app_name = default_app_name
        etree.SubElement(root, APPLICATION_TAG, attrib={APPLICATION_NAME_ATTRIBUTE: app_name})
        parsed_manifest.write(manifest_path)
    package = root.get(PACKAGE_TAG, '')
    return app_name, package
