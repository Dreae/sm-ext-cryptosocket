call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat"

cmake -A Win32 -DTARGET=windows -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release