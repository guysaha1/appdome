@echo off
pushd %~dp0 || goto error
if "%1" == "clean" goto clean
if "%1" == "unpack" goto unpack
if "%1" == "patch" goto patch
if "%1" == "pack" goto pack
if "%1" == "install" goto install

:usage
echo Usage: %0 unpack in.apk
echo or %0 patch
echo or %0 pack keystore password
echo or %0 install package
echo or %0 clean
goto end

:unpack
if "%2" == "" goto usage
echo Unpacking apk
CALL apktool d %2 -o unpacked_apk -f
goto end

:patch
pushd agent || goto error
echo Building agent
CALL build.bat || goto popd_and_error
popd || goto error

echo Patching apk
py -3 fusion_engine/fuse.py unpacked_apk agent/libs/armeabi-v7a/libagent.so || goto error
goto end

:pack
if "%2" == "" goto usage
if "%3" == "" goto usage
echo Repacking apk
CALL apktool b unpacked_apk -o out.tmp.apk
CALL zipalign -f 4 out.tmp.apk out.apk || goto error
CALL apksigner sign --ks %2 --ks-pass pass:%3 out.apk || goto error
goto end

:install
if "%2" == "" goto usage
adb uninstall %2
adb install out.apk || goto error
goto end

:popd_and_error
popd
:error
echo An error occurred: %errorlevel%, exiting
goto end

:clean
if exist unpacked_apk rmdir /S /Q unpacked_apk
if exist out.tmp.apk del /Q out.tmp.apk
if exist out.apk del /Q out.apk
:end
popd
exit /B
