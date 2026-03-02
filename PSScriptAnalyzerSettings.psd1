@{
    # Rules to exclude for this interactive console script project.
    # These rules are appropriate for reusable modules but not for
    # standalone entry-point scripts with intentional console output.
    ExcludeRules = @(
        # Interactive console scripts require Write-Host for coloured output
        'PSAvoidUsingWriteHost',

        # Global vars are the core state-sharing architecture of this entry-point script
        'PSAvoidGlobalVars',

        # Encoding choice — not a functional issue
        'PSUseBOMForUnicodeEncodedFile',

        # Intentionally empty catch blocks for non-critical operations (documented in comments)
        'PSAvoidUsingEmptyCatchBlock',

        # ShouldProcess (-WhatIf/-Confirm) is not appropriate for interactive CLI scripts
        'PSUseShouldProcessForStateChangingFunctions',

        # Plural noun function names are contextually clear and consistent across the project
        'PSUseSingularNouns',

        # False positives: parameters flagged as unused are referenced via string interpolation
        'PSReviewUnusedParameter'
    )
}
