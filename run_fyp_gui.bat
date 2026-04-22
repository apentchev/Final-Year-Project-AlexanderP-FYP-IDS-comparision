@echo off
echo ========================================
echo FYP GUI Launcher - DIAGNOSTIC MODE
echo ========================================
echo.

echo [DEBUG] Current directory: %CD%
echo [DEBUG] Looking for Python...

py --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    py --version
) else (
    python --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python
        python --version
    ) else (
        echo [ERROR] Python not found!
        pause
        exit /b 1
    )
)

echo.
echo [DEBUG] Checking for venv folder...
if not exist "venv\" (
    echo [DEBUG] venv not found, creating...
    %PYTHON_CMD% -m venv venv
    echo [DEBUG] venv created
) else (
    echo [DEBUG] venv folder exists
)

echo.
echo [DEBUG] Activating venv...
call venv\Scripts\activate.bat
echo [DEBUG] Python location after activation:
where python

echo.
echo [DEBUG] Checking for pandas...
pip show pandas
if errorlevel 1 (
    echo [DEBUG] pandas NOT found, installing...
    pip install pandas numpy matplotlib seaborn scikit-learn joblib
) else (
    echo [DEBUG] pandas IS installed
)

echo.
echo [DEBUG] About to run GUI...
echo [DEBUG] Running: python fyp_gui.py
echo.
python fyp_gui.py

echo.
echo ========================================
echo [DEBUG] Script finished
echo ========================================
pause