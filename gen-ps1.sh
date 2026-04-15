#!/bin/bash
set -e

for fw in net452 net472; do
    exe="${1}/${fw}/SharpSocks.exe"
    ps1="${1}/${fw}/SharpSocks.ps1"

    cat > "$ps1" <<EOF
\$b=[Convert]::FromBase64String("$(base64 -w0 "$exe")")
[Reflection.Assembly]::Load(\$b)|Out-Null
Write-Host '[SharpSocks.Agent.Entry]::Execute("arg1 arg2 arg3".Split())'
EOF
done
