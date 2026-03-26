# Kali MCP Pentest Bridge - Setup & Management Script
# Run from: C:\Users\thiru\Kali-Pentest-MCP\

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Show-Banner {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "     Kali MCP Pentest Bridge Manager" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Host "  [1] Start Server" -ForegroundColor Green
    Write-Host "  [2] Stop Server" -ForegroundColor Red
    Write-Host "  [3] Restart Server" -ForegroundColor Yellow
    Write-Host "  [4] View Logs" -ForegroundColor Cyan
    Write-Host "  [5] Check Status" -ForegroundColor Cyan
    Write-Host "  [6] Update Server" -ForegroundColor Magenta
    Write-Host "  [7] Run Initial Setup" -ForegroundColor Magenta
    Write-Host "  [8] Test SSH Connection" -ForegroundColor Yellow
    Write-Host "  [9] Clean Up" -ForegroundColor Red
    Write-Host "  [0] Exit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
}

function Load-Env {
    if (Test-Path "$ScriptDir\.env") {
        Get-Content "$ScriptDir\.env" | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
            }
        }
    } else {
        Write-Host "[ERROR] .env file not found at $ScriptDir\.env" -ForegroundColor Red
    }
}

function Fix-LineEndings {
    $scriptFile = "$ScriptDir\start-mcp-server.sh"
    if (Test-Path $scriptFile) {
        (Get-Content $scriptFile -Raw) -replace "`r`n", "`n" | Set-Content $scriptFile -NoNewline
        Write-Host "[OK] Line endings fixed in start-mcp-server.sh" -ForegroundColor Green
    }
}

function Start-Server {
    Write-Host ""
    Write-Host "[*] Starting Kali MCP Bridge..." -ForegroundColor Yellow
    Fix-LineEndings
    docker compose up -d --build
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "[*] Waiting for SSH master to establish..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $logs = docker logs kali-mcp-server 2>&1
        if ($logs -match "SSH master started") {
            Write-Host "[OK] Server started. SSH master connection established." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Server started but SSH master may not be ready. Check logs." -ForegroundColor Yellow
            Write-Host $logs
        }
    } else {
        Write-Host "[ERROR] Failed to start containers." -ForegroundColor Red
    }
}

function Stop-Server {
    Write-Host ""
    Write-Host "[*] Stopping Kali MCP Bridge..." -ForegroundColor Yellow
    docker compose down
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Server stopped." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to stop containers." -ForegroundColor Red
    }
}

function Restart-Server {
    Write-Host ""
    Write-Host "[*] Restarting Kali MCP Bridge..." -ForegroundColor Yellow
    Fix-LineEndings
    docker compose down
    docker compose up -d
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "[*] Waiting for SSH master to establish..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $logs = docker logs kali-mcp-server 2>&1
        if ($logs -match "SSH master started") {
            Write-Host "[OK] Server restarted. SSH master connection established." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Restarted but SSH master may not be ready. Check logs." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[ERROR] Failed to restart containers." -ForegroundColor Red
    }
}

function View-Logs {
    Write-Host ""
    Write-Host "Select log source:" -ForegroundColor Cyan
    Write-Host "  [1] kali-mcp-server (SSH relay)"
    Write-Host "  [2] mcp-bridge (Node.js bridge)"
    Write-Host "  [3] Both"
    $choice = Read-Host "Choice"
    Write-Host ""
    Write-Host "Press Ctrl+C to stop log streaming." -ForegroundColor Gray
    Write-Host ""
    switch ($choice) {
        "1" { docker logs -f kali-mcp-server }
        "2" { docker logs -f mcp-bridge }
        "3" {
            Write-Host "--- kali-mcp-server logs ---" -ForegroundColor Cyan
            docker logs kali-mcp-server
            Write-Host ""
            Write-Host "--- mcp-bridge logs (streaming) ---" -ForegroundColor Cyan
            docker logs -f mcp-bridge
        }
        default { Write-Host "[ERROR] Invalid choice." -ForegroundColor Red }
    }
}

function Check-Status {
    Write-Host ""
    Write-Host "============= Container Status =============" -ForegroundColor Cyan
    docker ps --filter "name=kali-mcp-server" --filter "name=mcp-bridge" --format "table {{.Names}}`t{{.Status}}`t{{.Ports}}"
    Write-Host ""
    Write-Host "============= Resource Usage ===============" -ForegroundColor Cyan
    docker stats --no-stream --format "table {{.Name}}`t{{.CPUPerc}}`t{{.MemUsage}}" kali-mcp-server mcp-bridge 2>$null
    Write-Host ""
    Write-Host "============= Bridge Health Check ==========" -ForegroundColor Cyan
    Load-Env
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$env:PORT/health" -TimeoutSec 5 -ErrorAction Stop
        $json = $response.Content | ConvertFrom-Json
        Write-Host "[OK] Bridge is healthy: $($json.status)" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Bridge not responding on port $env:PORT" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "============= SSH Master Status ============" -ForegroundColor Cyan
    $logs = docker logs kali-mcp-server 2>&1 | Select-String "SSH master"
    if ($logs) {
        Write-Host "[OK] $logs" -ForegroundColor Green
    } else {
        Write-Host "[WARN] SSH master status unknown — check full logs" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "============= Kali VM Connectivity =========" -ForegroundColor Cyan
    Load-Env
    $ping = Test-Connection -ComputerName $env:KALI_HOST -Count 1 -Quiet 2>$null
    if ($ping) {
        Write-Host "[OK] Kali VM ($env:KALI_HOST) is reachable" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Kali VM ($env:KALI_HOST) is NOT reachable" -ForegroundColor Red
    }
}

function Update-Server {
    Write-Host ""
    Write-Host "[*] Pulling latest changes from git..." -ForegroundColor Yellow
    git pull
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Git pull failed or no remote configured." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "[*] Rebuilding containers..." -ForegroundColor Yellow
    Fix-LineEndings
    docker compose down
    docker compose up -d --build
    if ($LASTEXITCODE -eq 0) {
        Start-Sleep -Seconds 5
        Write-Host "[OK] Update complete." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Rebuild failed." -ForegroundColor Red
    }
}

function Run-InitialSetup {
    Write-Host ""
    Write-Host "============= Initial Setup =================" -ForegroundColor Cyan
    Write-Host ""

    # Collect config
    $kaliHost = Read-Host "Enter Kali VM IP address (current: $(if (Test-Path .env) { (Get-Content .env | Select-String 'KALI_HOST').ToString().Split('=')[1] } else { 'not set' }))"
    if ([string]::IsNullOrWhiteSpace($kaliHost)) {
        Write-Host "[SKIP] Keeping existing KALI_HOST." -ForegroundColor Gray
    } else {
        # Update .env
        $envContent = Get-Content "$ScriptDir\.env" -Raw
        $envContent = $envContent -replace "KALI_HOST=.*", "KALI_HOST=$kaliHost"
        $envContent | Set-Content "$ScriptDir\.env" -NoNewline
        Write-Host "[OK] KALI_HOST updated to $kaliHost" -ForegroundColor Green
    }

    # Check SSH keys
    Write-Host ""
    if (Test-Path "$ScriptDir\ssh-keys\id_ed25519") {
        Write-Host "[OK] SSH key found at ssh-keys\id_ed25519" -ForegroundColor Green
    } else {
        Write-Host "[WARN] SSH key not found at ssh-keys\id_ed25519" -ForegroundColor Yellow
        Write-Host "       Generate one with: ssh-keygen -t ed25519 -f ssh-keys\id_ed25519 -N ''"
        Write-Host "       Then copy to Kali: ssh-copy-id -i ssh-keys\id_ed25519.pub root@<kali-ip>"
    }

    # Fix line endings
    Fix-LineEndings

    # Build and start
    Write-Host ""
    $start = Read-Host "Start containers now? (y/n)"
    if ($start -eq "y") {
        Start-Server
    }
}

function Test-SSHConnection {
    Write-Host ""
    Load-Env
    Write-Host "[*] Testing SSH connection to Kali VM ($env:KALI_HOST)..." -ForegroundColor Yellow
    Write-Host ""

    # Test from inside the kali-mcp-server container (the actual SSH path)
    $result = docker exec kali-mcp-server ssh `
        -i /root/.ssh/id_ed25519 `
        -o StrictHostKeyChecking=no `
        -o UserKnownHostsFile=/dev/null `
        -o ControlMaster=no `
        -o "ControlPath=/tmp/ssh_mux_$env:KALI_HOST" `
        -o ConnectTimeout=10 `
        root@$env:KALI_HOST "whoami && cat /etc/os-release | head -2 && echo SSH_TEST_OK" 2>&1

    if ($result -match "SSH_TEST_OK") {
        Write-Host "[OK] SSH connection successful!" -ForegroundColor Green
        Write-Host $result -ForegroundColor Gray
    } elseif ($result -match "ControlMaster") {
        Write-Host "[OK] Using existing SSH master tunnel (persistent connection active)" -ForegroundColor Green
        Write-Host $result -ForegroundColor Gray
    } else {
        Write-Host "[ERROR] SSH connection failed:" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Is the Kali VM running? (ping $env:KALI_HOST)"
        Write-Host "  2. Is the SSH key authorized on the Kali VM?"
        Write-Host "     ssh-copy-id -i ssh-keys\id_ed25519.pub root@$env:KALI_HOST"
        Write-Host "  3. Has the VM IP changed? Update .env KALI_HOST and restart."
    }
}

function Clean-Up {
    Write-Host ""
    Write-Host "[WARN] This will remove all containers, networks, and volumes." -ForegroundColor Red
    $confirm = Read-Host "Are you sure? Type 'yes' to confirm"
    if ($confirm -eq "yes") {
        Write-Host "[*] Cleaning up..." -ForegroundColor Yellow
        docker compose down -v --remove-orphans
        docker image rm kali-pentest-mcp-kali-mcp-server kali-pentest-mcp-mcp-bridge 2>$null
        Write-Host "[OK] Clean up complete." -ForegroundColor Green
    } else {
        Write-Host "[CANCELLED]" -ForegroundColor Gray
    }
}

# Main loop
while ($true) {
    Show-Banner
    Show-Menu
    $choice = Read-Host "Select option"
    Write-Host ""

    switch ($choice) {
        "1" { Start-Server }
        "2" { Stop-Server }
        "3" { Restart-Server }
        "4" { View-Logs }
        "5" { Check-Status }
        "6" { Update-Server }
        "7" { Run-InitialSetup }
        "8" { Test-SSHConnection }
        "9" { Clean-Up }
        "0" { Write-Host "Goodbye." -ForegroundColor Cyan; exit 0 }
        default { Write-Host "[ERROR] Invalid option. Please select 0-9." -ForegroundColor Red }
    }

    Write-Host ""
    Read-Host "Press Enter to return to menu"
}
