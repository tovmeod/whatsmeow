@echo off
echo Whatsmeow Shared Library Build Script

REM Define directories - we're now in go_test_helpers
set GO_HELPERS_DIR=%~dp0
set BIN_DIR=%GO_HELPERS_DIR%\bin

REM Define TDM-GCC path
set TDM_GCC_PATH=C:\TDM-GCC-64

REM Create bin directory if it doesn't exist
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo.
echo === Available commands ===
echo build     : Build the whatsmeow shared library
echo clean     : Clean the built library
echo help      : Show this help
echo.

if "%1"=="" goto :help
if "%1"=="build" goto :build
if "%1"=="clean" goto :clean
if "%1"=="help" goto :help

:help
echo Usage: build_go.bat [command]
echo.
echo Commands:
echo   build  - Build the whatsmeow shared library
echo   clean  - Remove built library files
echo   help   - Show this help message
echo.
echo The library will be built to: %BIN_DIR%\libwhatsmeow.dll
echo Run tests from the main pymeow directory using pytest
goto :eof

:build
echo Building whatsmeow shared library...
echo Working directory: %GO_HELPERS_DIR%
echo Output directory: %BIN_DIR%

REM Check if TDM-GCC exists
if not exist "%TDM_GCC_PATH%\bin" (
    echo Error: TDM-GCC not found at %TDM_GCC_PATH%
    echo Please verify the TDM-GCC installation path.
    exit /b 1
)

REM Add TDM-GCC to PATH temporarily for this build
echo Setting up TDM-GCC environment...
set "PATH=%TDM_GCC_PATH%\bin;%PATH%"

REM Verify compiler is available
echo Checking for GCC compiler...
gcc --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: GCC compiler not found in TDM-GCC.
    echo Please check your TDM-GCC installation.
    exit /b 1
)

echo ✓ GCC compiler found

REM Set CGO environment variables with suitable flags for TDM-GCC
echo Enabling CGO...
set CGO_ENABLED=1
set CC=%TDM_GCC_PATH%\bin\gcc.exe
set CXX=%TDM_GCC_PATH%\bin\g++.exe
set CGO_CFLAGS=-m64
set CGO_LDFLAGS=-m64

REM Set Windows-specific environment variables
set GOOS=windows
set GOARCH=amd64

REM Run go mod tidy to ensure dependencies are resolved
echo Running go mod tidy...
go mod tidy
if %ERRORLEVEL% neq 0 (
    echo Failed to run go mod tidy
    exit /b %ERRORLEVEL%
)

REM Build the shared library - build the entire whatsmeow library
echo Building shared library with TDM-GCC...
go build -buildmode=c-shared -o "%BIN_DIR%\libwhatsmeow.dll" .

if %ERRORLEVEL% neq 0 (
    echo Failed to build whatsmeow shared library
    echo.
    echo Troubleshooting tips:
    echo 1. Make sure Go is installed and in PATH
    echo 2. Verify TDM-GCC is properly installed at %TDM_GCC_PATH%
    echo 3. Check that go.mod file is properly configured
    echo 4. Ensure all Go source files are valid
    echo 5. Make sure TDM-GCC and Go are compatible versions
    exit /b %ERRORLEVEL%
)

echo.
echo ✓ Go whatsmeow library built successfully!
echo   Output: %BIN_DIR%\libwhatsmeow.dll
echo   Header: %BIN_DIR%\libwhatsmeow.h
echo   Used compiler: TDM-GCC
echo.
echo To run tests, navigate to the pymeow directory and run:
echo   python -m pytest pymeow/tests/test_eq -v
goto :eof

:clean
echo Cleaning Go whatsmeow library...
if exist "%BIN_DIR%\libwhatsmeow.dll" (
    del "%BIN_DIR%\libwhatsmeow.dll"
    echo Removed libwhatsmeow.dll
)
if exist "%BIN_DIR%\libwhatsmeow.h" (
    del "%BIN_DIR%\libwhatsmeow.h"
    echo Removed libwhatsmeow.h
)
echo Cleanup complete
goto :eof
