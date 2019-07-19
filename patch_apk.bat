@echo off
pushd %~dp0 || goto error

pushd agent || goto error
CALL build.bat || goto popd_and_error
popd || goto error

apktool d %1 -o unpacked_apk || goto error

python3 fusion_engine/fuse.py unpacked_apk agent/libs/armeabi-v7a/libagent.so || goto error

apktool b unpacked_apk -o %1 || goto error
REM zipalign, apksigner

goto end

:popd_and_error
popd
:error
echo An error occurred, exiting

:end
popd
exit /B
