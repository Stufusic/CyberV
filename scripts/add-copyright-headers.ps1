# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
#
# PROPRIETARY & SOURCE CODE LICENSE NOTICE
# This software is protected by international copyright laws and treaties.
# Unauthorized reproduction, reverse engineering, or distribution of this code,
# or any portion of it, is strictly prohibited without explicit written consent.
#
# DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
# OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
# ============================================================================

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RootDir

$HeaderSlash = @"
// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================

"@

$HeaderHash = @"
# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
#
# PROPRIETARY & SOURCE CODE LICENSE NOTICE
# This software is protected by international copyright laws and treaties.
# Unauthorized reproduction, reverse engineering, or distribution of this code,
# or any portion of it, is strictly prohibited without explicit written consent.
#
# DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
# OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
# ============================================================================

"@

$HeaderDash = @"
-- ============================================================================
-- CyberV - Stufusic
-- Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
--
-- PROPRIETARY & SOURCE CODE LICENSE NOTICE
-- This software is protected by international copyright laws and treaties.
-- Unauthorized reproduction, reverse engineering, or distribution of this code,
-- or any portion of it, is strictly prohibited without explicit written consent.
--
-- DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
-- THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
-- THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
-- OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
-- ============================================================================

"@

Write-Host "Đang cập nhật tiêu đề bản quyền: CyberV - Stufusic..." -ForegroundColor Cyan

$files = & git ls-files
$updatedCount = 0
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

foreach ($relPath in $files) {
    if ($relPath -match '^(tools|target|node_modules|dist|build|\.git)/') {
        continue
    }

    $ext = [System.IO.Path]::GetExtension($relPath).ToLower()
    $headerToAdd = $null

    if ($ext -in @('.rs', '.c', '.h', '.ts', '.tsx')) {
        $headerToAdd = $HeaderSlash
    } elseif ($ext -in @('.py', '.ps1')) {
        $headerToAdd = $HeaderHash
    } elseif ($ext -in @('.sql')) {
        $headerToAdd = $HeaderDash
    }

    if (-not $headerToAdd) {
        continue
    }

    $fullPath = Join-Path $RootDir $relPath
    if (-not (Test-Path $fullPath)) {
        continue
    }

    $content = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)

    # 1. Thay thế CyberV - Stufusic thành CyberV - Stufusic nếu đã có
    if ($content -match 'CyberV - Stufusic') {
        $content = $content.Replace('CyberV - Stufusic', 'CyberV - Stufusic')
        [System.IO.File]::WriteAllText($fullPath, $content, $utf8NoBom)
        $updatedCount++
        continue
    }

    # 2. Nếu đã có CyberV - Stufusic chuẩn rồi
    if ($content -match 'Copyright \(c\) 2024-2026 CyberV - Stufusic') {
        continue
    }

    # 3. Nếu chưa có header thì chèn mới
    $newContent = ""
    if ($ext -eq '.py') {
        $lines = $content -split "`r?`n"
        $prefixLines = @()
        $idx = 0
        while ($idx -lt $lines.Count -and ($lines[$idx].StartsWith('#!') -or $lines[$idx] -match '#.*coding[:=]')) {
            $prefixLines += $lines[$idx]
            $idx++
        }
        if ($prefixLines.Count -gt 0) {
            $prefix = ($prefixLines -join "`r`n") + "`r`n"
            $rest = ($lines[$idx..($lines.Count - 1)] -join "`r`n")
            $newContent = $prefix + $headerToAdd + $rest
        } else {
            $newContent = $headerToAdd + $content
        }
    } else {
        $newContent = $headerToAdd + $content
    }

    [System.IO.File]::WriteAllText($fullPath, $newContent, $utf8NoBom)
    $updatedCount++
}

Write-Host "====================================================" -ForegroundColor Green
Write-Host "HOÀN TẤT CẬP NHẬT HEADER BẢN QUYỀN!" -ForegroundColor Green
Write-Host "  - Số tệp đã cập nhật: $updatedCount" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
