$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:DEV_MODE = 'true'
$env:HOST = '127.0.0.1'
$env:PORT = '3000'
$env:APP_URL = 'http://127.0.0.1:3000'
node --env-file-if-exists=.env server.mjs
