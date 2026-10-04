# Starts local Ollama server if not already running
Write-Host "Checking Ollama connectivity..."
try {
    $res = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get -TimeoutSec 2
    Write-Host "Ollama server is already running on http://127.0.0.1:11434"
} catch {
    Write-Host "Starting Ollama server..."
    $ollamaPath = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
    if (Test-Path $ollamaPath) {
        & $ollamaPath serve
    } else {
        Write-Error "Ollama executable not found at $ollamaPath. Please install Ollama from https://ollama.ai"
    }
}
