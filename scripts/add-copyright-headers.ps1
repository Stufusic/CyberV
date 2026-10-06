# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
# Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
-- Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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

Write-Host "Đang quét các tệp mã nguồn CyberV để thêm bản quyền và miễn trừ trách nhiệm..." -ForegroundColor Cyan

# Lấy danh sách tệp được track bởi Git, loại trừ các thư mục phụ thuộc bên thứ 3
$files = & git ls-files
$updatedCount = 0
$skippedCount = 0

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
    if ($content -match 'Copyright \(c\) 2024-2026 Tersun - Stufusic') {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($fullPath, $content, $utf8NoBom)
        $skippedCount++
        continue
    }

    # Đối với Python hoặc script có shebang / coding pragma ở đầu
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

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $newContent, $utf8NoBom)
    $updatedCount++
}

Write-Host "====================================================" -ForegroundColor Green
Write-Host "HOÀN TẤT CẬP NHẬT HEADER BẢN QUYỀN!" -ForegroundColor Green
Write-Host "  - Số tệp đã thêm header: $updatedCount" -ForegroundColor Green
Write-Host "  - Số tệp đã có sẵn:       $skippedCount" -ForegroundColor Gray
Write-Host "====================================================" -ForegroundColor Green
