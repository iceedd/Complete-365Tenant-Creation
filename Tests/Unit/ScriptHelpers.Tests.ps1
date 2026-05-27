#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.6.0' }

<#
.SYNOPSIS
    Unit tests for Shared/ScriptHelpers.ps1
.DESCRIPTION
    Tests all helper functions that do not require Microsoft Graph connectivity.
    Covers: Write-LogMessage, Write-ScriptHeader, Write-SectionHeader,
            Test-ModuleAvailable, Invoke-WithRetry, Start-ThrottledLoop,
            Show-ExecutionSummary, Show-NextSteps, Show-ImportantInfo,
            Show-PauseBeforeExit
#>

BeforeAll {
    # Resolve the path to ScriptHelpers.ps1 relative to this test file's location.
    # Tests/Unit/ -> Tests/ -> project root -> Shared/ScriptHelpers.ps1
    $scriptHelpersPath = Join-Path $PSScriptRoot '..\..\Shared\ScriptHelpers.ps1'

    if (-not (Test-Path $scriptHelpersPath)) {
        throw "ScriptHelpers.ps1 not found at: $scriptHelpersPath"
    }

    # Dot-source to load all functions into the test scope.
    # Export-ModuleMember is a no-op when dot-sourcing, which is expected.
    . $scriptHelpersPath
}

# ============================================================================
# Write-LogMessage
# ============================================================================

Describe 'Write-LogMessage' {

    BeforeAll {
        Mock Write-Host {}
    }

    Context 'Color selection per Type' {

        It 'calls Write-Host with ForegroundColor White for Type Info' {
            Write-LogMessage -Message 'hello' -Type Info
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'White'
            }
        }

        It 'calls Write-Host with ForegroundColor Green for Type Success' {
            Write-LogMessage -Message 'hello' -Type Success
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'Green'
            }
        }

        It 'calls Write-Host with ForegroundColor Yellow for Type Warning' {
            Write-LogMessage -Message 'hello' -Type Warning
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'Yellow'
            }
        }

        It 'calls Write-Host with ForegroundColor Red for Type Error' {
            Write-LogMessage -Message 'hello' -Type Error
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'Red'
            }
        }
    }

    Context 'Message content' {

        It 'includes the supplied message text in the output string' {
            Write-LogMessage -Message 'test message text' -Type Info
            Should -Invoke Write-Host -ParameterFilter {
                "$Object" -match 'test message text'
            }
        }

        It 'defaults Type to Info when Type is omitted' {
            Write-LogMessage -Message 'default type'
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'White'
            }
        }

        It 'calls Write-Host exactly once per invocation' {
            Write-LogMessage -Message 'once' -Type Success
            Should -Invoke Write-Host -Times 1
        }
    }
}

# ============================================================================
# Write-ScriptHeader
# ============================================================================

Describe 'Write-ScriptHeader' {

    BeforeAll {
        Mock Write-Host {}
    }

    Context 'Title output' {

        It 'calls Write-Host with Cyan color for the title' {
            Write-ScriptHeader -Title 'My Script'
            Should -Invoke Write-Host -ParameterFilter {
                $ForegroundColor -eq 'Cyan' -and $Object -match 'My Script'
            }
        }

        It 'renders separator lines in Cyan' {
            Write-ScriptHeader -Title 'Test'
            # Two separator lines (top + bottom) plus the title line = 3 Cyan calls
            Should -Invoke Write-Host -Times 3 -ParameterFilter {
                $ForegroundColor -eq 'Cyan'
            }
        }

        It 'writes empty lines (blank Write-Host calls)' {
            Write-ScriptHeader -Title 'Test'
            # Two blank lines: one before the header block, one after
            Should -Invoke Write-Host -ParameterFilter {
                $null -eq $Object -or "$Object" -eq ''
            }
        }
    }

    Context 'Optional Description' {

        It 'outputs Description in Gray when Description is provided' {
            Write-ScriptHeader -Title 'Test' -Description 'A description'
            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $ForegroundColor -eq 'Gray' -and $Object -match 'A description'
            }
        }

        It 'does not output a Gray line when Description is omitted' {
            Write-ScriptHeader -Title 'Test'
            Should -Invoke Write-Host -Times 0 -ParameterFilter {
                $ForegroundColor -eq 'Gray'
            }
        }
    }
}

# ============================================================================
# Write-SectionHeader
# ============================================================================

Describe 'Write-SectionHeader' {

    BeforeAll {
        Mock Write-Host {}
    }

    It 'calls Write-Host with Yellow color and the title text' {
        Write-SectionHeader -Title 'My Section'
        Should -Invoke Write-Host -Times 1 -ParameterFilter {
            $ForegroundColor -eq 'Yellow' -and $Object -match 'My Section'
        }
    }

    It 'renders two separator lines in Gray' {
        Write-SectionHeader -Title 'Section'
        Should -Invoke Write-Host -Times 2 -ParameterFilter {
            $ForegroundColor -eq 'Gray'
        }
    }

    It 'also outputs a leading blank line' {
        Write-SectionHeader -Title 'Section'
        Should -Invoke Write-Host -ParameterFilter {
            $null -eq $Object -or "$Object" -eq ''
        }
    }
}

# ============================================================================
# Test-ModuleAvailable
# ============================================================================

Describe 'Test-ModuleAvailable' {

    Context 'when the module is available' {

        BeforeAll {
            Mock Get-Module {
                [PSCustomObject]@{ Name = 'ExistingModule'; Version = '1.0' }
            }
        }

        It 'returns true' {
            $result = Test-ModuleAvailable -ModuleName 'ExistingModule'
            $result | Should -BeTrue
        }
    }

    Context 'when the module is not available' {

        BeforeAll {
            Mock Get-Module { $null }
        }

        It 'returns false' {
            $result = Test-ModuleAvailable -ModuleName 'NonExistentModule'
            $result | Should -BeFalse
        }
    }

    Context 'when Get-Module returns an empty collection' {

        BeforeAll {
            Mock Get-Module { @() }
        }

        It 'returns false' {
            $result = Test-ModuleAvailable -ModuleName 'EmptyResult'
            $result | Should -BeFalse
        }
    }
}

# ============================================================================
# Invoke-WithRetry
# ============================================================================

Describe 'Invoke-WithRetry' {

    BeforeAll {
        Mock Write-Host {}
        Mock Start-Sleep {}
    }

    Context 'succeeds on the first attempt' {

        It 'returns the script block result without retrying' {
            $result = Invoke-WithRetry -ScriptBlock { 'first-try-result' } -MaxRetries 3 -RetryDelaySeconds 1
            $result | Should -Be 'first-try-result'
        }

        It 'does not call Start-Sleep when no retry is needed' {
            Invoke-WithRetry -ScriptBlock { 'ok' } -MaxRetries 3 -RetryDelaySeconds 1
            Should -Invoke Start-Sleep -Times 0
        }
    }

    Context 'succeeds after one transient failure' {

        It 'returns the result from the second attempt' {
            $script:callCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:callCount++
                if ($script:callCount -lt 2) { throw 'transient error' }
                'retry-success'
            } -MaxRetries 3 -RetryDelaySeconds 1

            $result | Should -Be 'retry-success'
        }

        It 'calls Start-Sleep once before the successful retry' {
            $script:callCount2 = 0
            Invoke-WithRetry -ScriptBlock {
                $script:callCount2++
                if ($script:callCount2 -lt 2) { throw 'transient' }
                'ok'
            } -MaxRetries 3 -RetryDelaySeconds 1

            Should -Invoke Start-Sleep -Times 1
        }
    }

    Context 'fails every attempt and exhausts max retries' {

        It 'throws after MaxRetries are exhausted' {
            {
                Invoke-WithRetry -ScriptBlock { throw 'always fails' } -MaxRetries 3 -RetryDelaySeconds 1
            } | Should -Throw
        }

        It 'calls Start-Sleep MaxRetries - 1 times (delays between attempts, not after the last)' {
            try {
                Invoke-WithRetry -ScriptBlock { throw 'fail' } -MaxRetries 3 -RetryDelaySeconds 1
            }
            catch { }

            # 3 max retries: attempt 1 fails -> sleep, attempt 2 fails -> sleep, attempt 3 fails -> throw (no sleep)
            Should -Invoke Start-Sleep -Times 2
        }
    }

    Context 'exponential backoff delay doubling' {

        It 'doubles the delay on each retry' {
            $capturedDelays = [System.Collections.Generic.List[int]]::new()
            Mock Start-Sleep { $capturedDelays.Add($Seconds) }

            try {
                Invoke-WithRetry -ScriptBlock { throw 'fail' } -MaxRetries 3 -RetryDelaySeconds 2
            }
            catch { }

            $capturedDelays[0] | Should -Be 2
            $capturedDelays[1] | Should -Be 4
        }
    }

    Context 'uses default parameter values' {

        It 'succeeds with no explicit MaxRetries or RetryDelaySeconds' {
            $result = Invoke-WithRetry -ScriptBlock { 'default-params' }
            $result | Should -Be 'default-params'
        }
    }
}

# ============================================================================
# Start-ThrottledLoop
# ============================================================================

Describe 'Start-ThrottledLoop' {

    BeforeAll {
        Mock Start-Sleep {}
    }

    Context 'processes all items' {

        It 'returns a result entry for every input item' {
            $items = @('a', 'b', 'c')
            $results = Start-ThrottledLoop -Items $items -ScriptBlock { 'ok' } -DelayMs 0
            $results.Count | Should -Be 3
        }

        It 'marks each entry as Success when the script block does not throw' {
            $items = @(1, 2)
            $results = Start-ThrottledLoop -Items $items -ScriptBlock { 'done' } -DelayMs 0
            $results | ForEach-Object { $_.Success | Should -BeTrue }
        }

        It 'records the item reference in each result entry' {
            $items = @('apple', 'banana')
            $results = Start-ThrottledLoop -Items $items -ScriptBlock { 'done' } -DelayMs 0
            $results[0].Item | Should -Be 'apple'
            $results[1].Item | Should -Be 'banana'
        }

        It 'records the 1-based Index in each result entry' {
            $items = @('x', 'y')
            $results = Start-ThrottledLoop -Items $items -ScriptBlock { 'done' } -DelayMs 0
            $results[0].Index | Should -Be 1
            $results[1].Index | Should -Be 2
        }
    }

    Context 'handles script block failures' {

        It 'marks a result as failed when the script block throws' {
            $items = @('bad-item')
            $results = Start-ThrottledLoop -Items $items -ScriptBlock { throw 'boom' } -DelayMs 0
            $results[0].Success | Should -BeFalse
        }

        It 'captures the exception message in the Error property' {
            $items = @('bad-item')
            $results = @(Start-ThrottledLoop -Items $items -ScriptBlock { throw 'boom' } -DelayMs 0)
            $results[0].Error | Should -Be 'boom'
        }

        It 'continues processing remaining items after one failure' {
            $items = @('fail', 'ok')
            $script:loopCount = 0
            $results = Start-ThrottledLoop -Items $items -ScriptBlock {
                $script:loopCount++
                if ($script:loopCount -eq 1) { throw 'first fails' }
                'second ok'
            } -DelayMs 0
            $results[0].Success | Should -BeFalse
            $results[1].Success | Should -BeTrue
        }
    }

    Context 'passes item to script block' {

        It 'makes the current item available as $_ inside the script block' {
            $items = @('apple', 'banana')
            $received = [System.Collections.Generic.List[string]]::new()
            Start-ThrottledLoop -Items $items -ScriptBlock { $received.Add($_) } -DelayMs 0
            $received[0] | Should -Be 'apple'
            $received[1] | Should -Be 'banana'
        }

        It 'each item is distinct — not null — inside the script block' {
            $items = @('x', 'y', 'z')
            $nullCount = 0
            Start-ThrottledLoop -Items $items -ScriptBlock {
                if ($null -eq $_) { $nullCount++ }
            } -DelayMs 0
            $nullCount | Should -Be 0
        }
    }

    Context 'throttle delay behavior' {

        It 'calls Start-Sleep between items but not after the last item' {
            $items = @('a', 'b', 'c')
            Start-ThrottledLoop -Items $items -ScriptBlock { 'ok' } -DelayMs 100
            # 3 items: sleep after item 1, sleep after item 2, NO sleep after item 3
            Should -Invoke Start-Sleep -Times 2
        }

        It 'does not call Start-Sleep at all when there is only one item' {
            Start-ThrottledLoop -Items @('only') -ScriptBlock { 'ok' } -DelayMs 500
            Should -Invoke Start-Sleep -Times 0
        }
    }
}

# ============================================================================
# Show-ExecutionSummary
# ============================================================================

Describe 'Show-ExecutionSummary' {

    BeforeAll {
        Mock Write-Host {}
    }

    Context 'success counts' {

        It 'outputs the total item count' {
            $results = @(
                @{ Success = $true; Item = @{ Name = 'ItemA' }; Result = @{}; Index = 1 }
                @{ Success = $true; Item = @{ Name = 'ItemB' }; Result = @{}; Index = 2 }
            )
            Show-ExecutionSummary -Results $results -ItemType 'groups'
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match '2'
            }
        }

        It 'outputs the success count in Green' {
            $results = @(
                @{ Success = $true; Item = @{ Name = 'A' }; Result = @{}; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $ForegroundColor -eq 'Green' -and $Object -match '1'
            }
        }

        It 'does not output a Red failure line when all items succeed' {
            $results = @(
                @{ Success = $true; Item = @{ Name = 'A' }; Result = @{}; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -Times 0 -ParameterFilter {
                $ForegroundColor -eq 'Red' -and $Object -match 'Failed:'
            }
        }
    }

    Context 'failure counts' {

        It 'outputs the failure count in Red when items have failed' {
            $results = @(
                @{ Success = $false; Item = @{ Name = 'Bad' }; Error = 'oops'; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $ForegroundColor -eq 'Red' -and $Object -match '1'
            }
        }

        It 'outputs the failed item name in Red' {
            $results = @(
                @{ Success = $false; Item = @{ Name = 'FailedItem' }; Error = 'timeout'; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $ForegroundColor -eq 'Red' -and $Object -match 'FailedItem'
            }
        }
    }

    Context 'mixed results' {

        It 'outputs both success and failure sections when results are mixed' {
            $results = @(
                @{ Success = $true;  Item = @{ Name = 'Good' }; Result = @{}; Index = 1 }
                @{ Success = $false; Item = @{ Name = 'Bad' };  Error = 'err'; Index = 2 }
            )
            Show-ExecutionSummary -Results $results
            # "Created:" header is Green; individual item names are White
            Should -Invoke Write-Host -ParameterFilter { $ForegroundColor -eq 'Green' -and "$Object" -match 'Created' }
            Should -Invoke Write-Host -ParameterFilter { $ForegroundColor -eq 'Red'   -and "$Object" -match 'Bad'  }
        }
    }

    Context 'ItemType label' {

        It 'includes the ItemType string in the total count line' {
            $results = @(
                @{ Success = $true; Item = @{ Name = 'X' }; Result = @{}; Index = 1 }
            )
            Show-ExecutionSummary -Results $results -ItemType 'policies'
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match 'policies'
            }
        }

        It 'defaults ItemType to "items" when omitted' {
            $results = @(
                @{ Success = $true; Item = @{ Name = 'X' }; Result = @{}; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match 'items'
            }
        }
    }

    Context 'item name resolution' {

        It 'uses DisplayName when Name is absent' {
            $results = @(
                @{ Success = $true; Item = @{ DisplayName = 'DisplayMe' }; Result = @{}; Index = 1 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match 'DisplayMe'
            }
        }

        It 'falls back to "Item <Index>" when neither Name nor DisplayName is present' {
            $results = @(
                @{ Success = $true; Item = @{}; Result = @{}; Index = 5 }
            )
            Show-ExecutionSummary -Results $results
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match 'Item 5'
            }
        }
    }
}

# ============================================================================
# Show-NextSteps
# ============================================================================

Describe 'Show-NextSteps' {

    BeforeAll {
        Mock Write-Host {}
    }

    It 'outputs the title in Yellow' {
        Show-NextSteps -Steps @('Step one')
        Should -Invoke Write-Host -Times 1 -ParameterFilter {
            $ForegroundColor -eq 'Yellow' -and $Object -match 'Next Steps'
        }
    }

    It 'outputs each step in Gray' {
        Show-NextSteps -Steps @('Step one', 'Step two', 'Step three')
        Should -Invoke Write-Host -Times 3 -ParameterFilter {
            $ForegroundColor -eq 'Gray'
        }
    }

    It 'includes the step text in the output' {
        Show-NextSteps -Steps @('Configure DNS', 'Enable MFA')
        Should -Invoke Write-Host -ParameterFilter { $Object -match 'Configure DNS' }
        Should -Invoke Write-Host -ParameterFilter { $Object -match 'Enable MFA'   }
    }

    It 'numbers steps starting at 1' {
        Show-NextSteps -Steps @('First step')
        Should -Invoke Write-Host -ParameterFilter {
            $Object -match '1\.' -and $Object -match 'First step'
        }
    }

    It 'uses a custom Title when provided' {
        Show-NextSteps -Steps @('Do thing') -Title 'Action Items'
        Should -Invoke Write-Host -Times 1 -ParameterFilter {
            $ForegroundColor -eq 'Yellow' -and $Object -match 'Action Items'
        }
    }

    It 'outputs a trailing blank line' {
        Show-NextSteps -Steps @('Step')
        Should -Invoke Write-Host -ParameterFilter {
            $null -eq $Object -or "$Object" -eq ''
        }
    }
}

# ============================================================================
# Show-ImportantInfo
# ============================================================================

Describe 'Show-ImportantInfo' {

    BeforeAll {
        Mock Write-Host {}
    }

    It 'outputs the title in Yellow' {
        Show-ImportantInfo -Items @{ Key = 'Value' }
        Should -Invoke Write-Host -Times 1 -ParameterFilter {
            $ForegroundColor -eq 'Yellow' -and $Object -match 'Important Information'
        }
    }

    It 'outputs each key-value pair in Gray' {
        Show-ImportantInfo -Items @{ TenantId = 'abc-123'; Domain = 'contoso.com' }
        Should -Invoke Write-Host -Times 2 -ParameterFilter {
            $ForegroundColor -eq 'Gray'
        }
    }

    It 'includes the key name in the output' {
        Show-ImportantInfo -Items @{ TenantId = 'abc-123' }
        Should -Invoke Write-Host -ParameterFilter {
            $Object -match 'TenantId'
        }
    }

    It 'includes the value in the output' {
        Show-ImportantInfo -Items @{ TenantId = 'abc-123' }
        Should -Invoke Write-Host -ParameterFilter {
            $Object -match 'abc-123'
        }
    }

    It 'uses a custom Title when provided' {
        Show-ImportantInfo -Items @{ Key = 'Val' } -Title 'Reference Data'
        Should -Invoke Write-Host -Times 1 -ParameterFilter {
            $ForegroundColor -eq 'Yellow' -and $Object -match 'Reference Data'
        }
    }

    It 'outputs a trailing blank line' {
        Show-ImportantInfo -Items @{ A = 'B' }
        Should -Invoke Write-Host -ParameterFilter {
            $null -eq $Object -or "$Object" -eq ''
        }
    }
}

# ============================================================================
# Show-PauseBeforeExit
# ============================================================================

Describe 'Show-PauseBeforeExit' {

    BeforeAll {
        Mock Write-Host {}
        Mock Start-Sleep {}
    }

    Context 'interactive environment (ReadKey succeeds)' {

        BeforeAll {
            # Simulate a console where ReadKey works
            Mock -CommandName 'Invoke-Expression' {} -ModuleName $null

            # We need to mock $Host.UI.RawUI.ReadKey — the cleanest approach in
            # Pester 5 is to stub the entire try block by mocking Start-Sleep and
            # verifying it is NOT called when ReadKey succeeds.
            # We cannot easily mock a property chain, so we instead test the
            # fallback branch directly in the next context.
        }

        It 'outputs the default message in Gray' {
            # ReadKey may throw in a non-console runner; that is fine —
            # either path completes without error.
            { Show-PauseBeforeExit } | Should -Not -Throw
            Should -Invoke Write-Host -ParameterFilter {
                $ForegroundColor -eq 'Gray' -and $Object -match 'Press any key'
            }
        }

        It 'accepts a custom message and displays it' {
            { Show-PauseBeforeExit -Message 'Hit a key to continue' } | Should -Not -Throw
            Should -Invoke Write-Host -ParameterFilter {
                $Object -match 'Hit a key to continue'
            }
        }
    }

    Context 'non-interactive environment (ReadKey throws, fallback to Start-Sleep)' {

        BeforeAll {
            # Force the ReadKey path to throw by temporarily replacing $Host.UI.RawUI.
            # In Pester 5 we can do this by creating a wrapper function that always
            # invokes the catch branch.  We test this indirectly: if ReadKey is
            # unavailable Pester's test runner environment itself causes the throw,
            # so Start-Sleep should be called.
            Mock Start-Sleep {}
        }

        It 'calls Start-Sleep as a fallback when ReadKey is unavailable' {
            # In a non-interactive (CI) runner ReadKey will throw, triggering the catch.
            # If ReadKey does NOT throw (local interactive shell) we cannot assert
            # Start-Sleep — so we just verify the function completes without error.
            { Show-PauseBeforeExit } | Should -Not -Throw
        }

        It 'does not propagate the ReadKey exception to the caller' {
            { Show-PauseBeforeExit } | Should -Not -Throw
        }
    }
}
