@echo off
setlocal
cd /d "%~dp0"
set "ROOT=%cd%"
set "ERR=0"

echo ============================================================
echo  Bingo - prerequisite check ^& startup
echo ============================================================
echo.

where docker >nul 2>&1
if errorlevel 1 ( echo [MISSING] Docker is not installed or not on PATH. & set "ERR=1" )

docker info >nul 2>&1
if errorlevel 1 ( echo [MISSING] Docker daemon is not running - start Docker Desktop. & set "ERR=1" )

set "PYLAUNCH="
where py >nul 2>&1 && set "PYLAUNCH=py -3.12"
if not defined PYLAUNCH ( where python >nul 2>&1 && set "PYLAUNCH=python" )
if not defined PYLAUNCH ( echo [MISSING] Python 3.12 not found - install from python.org. & set "ERR=1" )

set "OFFCFG=%ROOT%\Ai-Agent\Offensive-Agent\config.yaml"
set "SECLISTS_COMMON="
if exist "%OFFCFG%" for /f tokens^=2^ delims^=^" %%A in ('findstr /c:"common:" "%OFFCFG%" 2^>nul') do set "SECLISTS_COMMON=%%A"
if not defined SECLISTS_COMMON set "SECLISTS_COMMON=%ROOT%\SecLists\Discovery\Web-Content\common.txt"
if not exist "%SECLISTS_COMMON%" (
    echo [WARN]    SecLists wordlist from config.yaml not found:
    echo              %SECLISTS_COMMON%
    echo           Set paths.wordlists.common in Ai-Agent\Offensive-Agent\config.yaml, or clone SecLists:
    echo           git clone https://github.com/danielmiessler/SecLists.git "%ROOT%\SecLists"
)

if not exist "%ROOT%\Ai-Agent\.env" (
    echo [MISSING] Ai-Agent\.env - copy Ai-Agent\.env.example and set OPENAI_API_KEY + REPORTING_API_KEY.
    set "ERR=1"
)
if not exist "%ROOT%\Back-end\.env" (
    echo [WARN]    Back-end\.env missing - copy Back-end\.env.example before first run.
)

for %%F in (
    "Ai-Agent\Bingo_Agent.py"
    "Ai-Agent\Offensive-Agent\config.yaml"
    "Ai-Agent\Offensive-Agent\scan_runner.py"
    "Ai-Agent\Defensive-Agent\waf_model.pkl"
    "Ai-Agent\requirements.txt"
    "Ai-Agent\requirements-gui.txt"
    "docker-compose.yml"
    "docker-compose.agent.yml"
) do (
    if not exist "%ROOT%\%%~F" ( echo [MISSING] %%~F & set "ERR=1" )
)

if not "%ERR%"=="0" (
    echo.
    echo Prerequisite check FAILED. Fix the items above and run start.bat again.
    exit /b 1
)

echo All prerequisites present.
echo NOTE: SecLists is read from paths.wordlists.common in config.yaml
echo       ^(currently: %SECLISTS_COMMON%^).
echo       If you moved the project, update that path in Ai-Agent\Offensive-Agent\config.yaml.
echo.

if not exist "%ROOT%\Ai-Agent\.venv\Scripts\python.exe" (
    echo [setup] Creating virtual environment and installing dependencies...
    pushd "%ROOT%\Ai-Agent"
    %PYLAUNCH% -m venv .venv
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    ".venv\Scripts\python.exe" -m pip install -r requirements-gui.txt
    ".venv\Scripts\python.exe" -m playwright install chromium
    popd
) else (
    echo [setup] Virtual environment present - skipping dependency install.
)
echo.

echo [docker] Starting platform + DVWA ^(first run builds images, this can take a while^)...
docker compose -f docker-compose.yml -f docker-compose.agent.yml up -d --build db app webserver frontend dvwa
docker compose -f docker-compose.yml -f docker-compose.agent.yml exec -T app composer install --no-interaction
docker compose -f docker-compose.yml -f docker-compose.agent.yml exec -T app php artisan migrate --force
docker compose -f docker-compose.yml -f docker-compose.agent.yml exec -T app php artisan db:seed --class=AdminSeeder --force

echo.
echo ============================================================
echo  Platform is up:
echo    Dashboard : http://localhost:5500
echo    Login     : admin@bingo.local / BingoAdmin2026!
echo    API       : http://localhost:8000/api
echo    DVWA      : http://localhost:4280
echo ============================================================
echo.

echo [agent] Launching the Bingo behavioral agent...
cd /d "%ROOT%\Ai-Agent"
".venv\Scripts\python.exe" Bingo_Agent.py

endlocal
