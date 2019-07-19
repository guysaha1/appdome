from consts import *
from typing import Iterable, AnyStr

METHOD_CONTENT_TO_ADD = b'''    const-string v0, "%s"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
'''
METHOD_TO_REPLACE = b'.method static constructor <clinit>()V'
LOCALS_DECLARATION = b'.locals'
SMALI_METHOD_TEMPLATE = b'''%s
    %s 1
%s
    return-void
.end method'''
SMALI_FILE_TEMPLATE = b'''.class public L%s;
.super Landroid/app/Application;

%s
'''


def find_prefix(collection: Iterable[AnyStr], prefix: AnyStr, start: int = 0) -> int:
    for i, v in enumerate(collection[start:], start=start):
        if v.strip().startswith(prefix):
            return i
    return -1


def patch_smali_file(smali_file: Path, agent_name: str, apk_dir: Path):
    patched_content = METHOD_CONTENT_TO_ADD % (agent_name.encode(),)
    if smali_file.exists():
        smali_lines = smali_file.read_bytes().splitlines(keepends=True)
        method_index = find_prefix(smali_lines, METHOD_TO_REPLACE)
        if method_index == -1:
            patched_content = SMALI_METHOD_TEMPLATE % (METHOD_TO_REPLACE, LOCALS_DECLARATION, patched_content)
            index_to_patch = len(smali_lines)
        else:
            index_to_patch = find_prefix(smali_lines, LOCALS_DECLARATION, start=method_index + 1) + 1
            if index_to_patch == 0:
                raise ValueError('Could not find locals declaration in clinit method in {}'.format(smali_file))
    else:
        smali_lines = []
        index_to_patch = 0
        patched_content = SMALI_METHOD_TEMPLATE % (METHOD_TO_REPLACE, LOCALS_DECLARATION, patched_content)
        class_name = Path(smali_file.relative_to(apk_dir).parts[1:]).as_posix()
        patched_content = SMALI_FILE_TEMPLATE % (class_name.encode(), patched_content)
    with smali_file.open('wb') as f:
        f.write(b''.join(smali_lines[:index_to_patch]))
        f.write(patched_content)
        f.write(b''.join(smali_lines[index_to_patch:]))
