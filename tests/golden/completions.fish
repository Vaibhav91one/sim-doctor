# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_sim_doctor_global_optspecs
    string join \n h/help V/version
end

function __fish_sim_doctor_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_sim_doctor_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_sim_doctor_using_subcommand
    set -l cmd (__fish_sim_doctor_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -s V -l version -d 'Print version'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "modules" -d 'Describe the crate module roots and the layering between them'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "scan" -d 'Select a card\'s master file, walk everything under it, and report'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "ts48" -d 'Compare a card against the public GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "install" -d 'Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "ci" -d 'Write the GitHub Actions workflow that runs this repo\'s action on pull requests'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "completions" -d 'Write a shell completion script to stdout'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "mcp" -d 'Serve the scan and the rules as MCP tools over stdio'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "rules" -d 'List the rules a scan runs, or explain one, without a card'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "why" -d 'Explain a rule, or every rule in a saved `scan --json` envelope'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "fix" -d 'Hand one finding from a saved scan to a coding agent'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "gp" -d 'Read-only GlobalPlatform queries'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "trace" -d 'Decode a captured APDU trace offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "fuzz" -d 'APDU discovery and the OTA/SMS fuzz sweep'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "euicc" -d 'eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes'
complete -c sim-doctor -n "__fish_sim_doctor_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand modules" -l json -d 'Emit the JSON envelope on stdout instead of a human-readable table'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand modules" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l dialect -d 'Which FCP tag table this card answers SELECT with' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-depth -d 'Deepest path below the master file the walk descends into' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-children -d 'Identifiers probed per directory' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-nodes -d 'Files the card selected across the whole walk (default 16384)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l max-directories -d 'Directories whose children are enumerated' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l severity -d 'Drop findings below this severity' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l baseline -d 'Compare this run against a previous `scan --json` envelope (doctor/1)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l fail-on -d 'Exit 1 (3 under --baseline) when a finding is at or above this severity' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l sarif -d 'Also write the findings to FILE as SARIF 2.1.0' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l tar -d 'Which TARs to probe for MSL 0, and how many' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l face -d 'Print the findings with a doctor-kit face instead of the full report' -r -f -a "plain\t'Minimalist text, one line per finding'
rich\t'Boxed report with a score gauge, grouped by category'
compact\t'One-line summary plus a findings table'"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l theme -d 'The face\'s colours: mono, clinical or contrast (default: the tool\'s own)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l color -d 'Colour the face: auto (a terminal and no NO_COLOR), always or never' -r -f -a "auto\t''
always\t''
never\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l tui -d 'Show the findings in an interactive terminal view instead of the report'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l score -d 'Add one quality score for this card, for CI gating'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l terminal-profile -d 'Send a TERMINAL PROFILE to the card before the TAR audit'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -l headless -d 'A face in plain text without colour, for CI and pipes'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand scan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and not __fish_seen_subcommand_from compare help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l dialect -d 'Which FCP tag table this card answers SELECT with (see `scan --help`)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-depth -d 'Deepest path below the master file the walk descends into' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-children -d 'Identifiers probed per directory' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-nodes -d 'Files the card selected across the whole walk (default 16384)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l max-directories -d 'Directories whose children are enumerated' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -l json -d 'Emit one JSON envelope (type "ts48") on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from compare" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from help" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ts48; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l agent -d 'Install for one agent only; omit for all of them' -r -f -a "claude\t''
cursor\t''
codex\t''
opencode\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l dir -d 'Project root to write under (default: the current directory)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -l print-only -d 'Print what would be written instead of writing it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and not __fish_seen_subcommand_from install help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l swsim -d 'Build the software card on the runner (CI has no card otherwise)' -r -f -a "true\t''
false\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l baseline -d 'Committed baseline path (letters, digits and . _ / - only)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l require-baseline -d 'Fail the job when the baseline file is missing' -r -f -a "true\t''
false\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l severity -d 'Pass --severity to the scan' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l ref -d 'The action ref to pin (default: v<this version>; it exists once that release is cut)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l dir -d 'Project root to write under (default: the current directory)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l force -d 'Overwrite a differing existing workflow'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -l print-only -d 'Print the workflow instead of writing it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from help" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand ci; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand mcp" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and not __fish_seen_subcommand_from list explain help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from list" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from explain" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand rules; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand why" -l json -d 'Emit one JSON envelope of kind "rules" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand why" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l from -d 'A saved `sim-doctor scan --json` envelope holding a finding for that rule' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l agent -d 'Start this coding agent with the prompt instead of only printing it' -r -f -a "claude\t''
codex\t''
cursor\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -l skip-approvals -d 'Pass the agent its flag that skips approval prompts (unverified for every CLI version)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fix" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and not __fish_seen_subcommand_from info ara status select channel delete install put-key help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from ara" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l aid -d 'The application AID, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from select" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "open" -d 'MANAGE CHANNEL open: the card picks the number and it is printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "close" -d 'MANAGE CHANNEL close of a channel opened earlier'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from channel" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l aid -d 'The AID to delete, 5 to 16 bytes of hex' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l related -d 'Also delete related objects (P2 80): for a load file, its applications'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l load -d 'The CAP file (a zip of javacard/*.cap components)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l module -d 'The Executable Module AID (the applet class). Optional when the CAP has one applet' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l app -d 'The application (instance) AID. Defaults to the module AID' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l params -d 'The Install Parameters field as TLV with the mandatory C9 tag (default C900: none)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l privileges -d 'Privileges, 1 or 3 bytes of hex (default 000000). Card Lock and Card Terminate are refused' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-key-file -d 'File holding the AES DAP key (hex, optionally KEY/KCV; chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-key-env -d 'Environment variable holding the AES DAP key' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-sd -d 'The Security Domain that verifies the DAP, 5 to 16 bytes of hex (default: the issuer security domain being authenticated)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l dap-hash -d 'The Load File Data Block Hash the DAP signs' -r -f -a "sha256\t''
sha384\t''
sha512\t''"
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from install" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-key-version -d 'The Key Version Number of the new keys, 01 to 7F' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l replace-key-version -d 'P1: 00 (default) adds the key set; 01 to 7F replaces the key set with that version' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l key-id -d 'The Key Identifier of the first key (the other two follow at +1 and +2)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-keys-file -d 'File holding the new keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l new-keys-env -d 'Environment variable holding the new keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l keys-file -d 'File holding the keys (keep it chmod 600)' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l keys-env -d 'Environment variable holding the keys' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l key-version -d 'Key version number for INITIALIZE UPDATE, two hex digits; 00 (default) lets the card choose its first key set' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l channel -d 'Logical channel number, 0 (the basic channel, default) to 19. The SELECT and every following command, and the secure channel, use it' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l replace-current-keyset -d 'Allow the request to add, replace or overwrite the key version this session authenticated with. Without it such a request is refused'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l json -d 'Emit one JSON envelope of kind "gp" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l trace -d 'Add every APDU exchange (command and response hex) as data.trace'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -l yes -d 'Send the commands. Without it nothing is written. Needs --keys-file or --keys-env'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from put-key" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand gp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -l json -d 'Emit one JSON envelope of kind "trace" on stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand trace" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate help" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate help" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate help" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and not __fish_seen_subcommand_from apdu ota mutate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l level -d '1 for CLA discovery, 2 for CLA+INS discovery' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l class -d 'The CLA level 2 probes INS values at, as two hex digits (e.g. A0). Required for --level 2' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l i-understand-this-can-brick-the-card -d 'Required. Without it, `fuzz` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l allow-real-hardware -d 'Required in addition to the opt-in above when the reader\'s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, `fuzz` refuses to run against anything that is not recognisably the software card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -l quick -d 'Probe a small, documented subset instead of the full space'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from apdu" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l i-understand-this-can-brick-the-card -d 'Required. Without it, `fuzz` refuses to run at all (exit 1, error kind fuzz-needs-opt-in)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l allow-real-hardware -d 'Required in addition to the opt-in above when the reader\'s name does not match the software card (swicc-pcsc names its reader with "swICC"). Without it, `fuzz` refuses to run against anything that is not recognisably the software card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -l quick -d 'Probe a small, documented subset instead of the full space'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from ota" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l replay -d 'Answer from a recorded exchange log (one {"command","response"} JSON object per line, as SIM_DOCTOR_RECORD writes) instead of a card' -r -F
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l max-cases -d 'Cases to send (1 to 10000)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l timeout -d 'Stop sending after this many seconds' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l seed -d 'PRNG seed. The same seed gives the same APDUs' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l mock -d 'Answer from the built-in strict mock card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l dry-run -d 'Print the planned APDUs and the allowlist/denylist; send nothing'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l stop-on-first-finding -d 'Stop after the first finding'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -l json -d 'Emit one JSON envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from mutate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand fuzz; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and not __fish_seen_subcommand_from info profiles notifications nickname enable disable delete reset help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from profiles" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "remove" -d 'Remove a notification from the eUICC\'s list (lpac `notification remove`, ES10b RemoveNotificationFromList). A dry run unless `--yes`: a removed notification is never sent to the operator\'s server. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "dump" -d 'Read the full signed pending notifications (lpac `notification dump`, ES10b RetrieveNotificationsList) as a re-loadable JSON document: hex of the signed bytes plus the decoded sequence number, operation, address and ICCID. Read-only: nothing is removed. Without `-o` and `--json` the document itself is printed. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "replay" -d 'Send the notifications of a dump file to their operators (ES9+ HandleNotification over HTTPS). A dry run unless `--yes`: this reaches the network and tells the operator\'s server about a profile event. Needs no card and removes nothing. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from notifications" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l yes -d 'Send SetNickname, then re-read the profile list and confirm. Without it nothing is changed: the target EID and ICCID, the current and the new nickname are printed and the command exits'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from nickname" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l yes -d 'Send the request, then re-read the profile list and confirm. Without it nothing is changed: the plan and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l yes -d 'Send the request, then re-read the profile list and confirm. Without it nothing is changed: the plan and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l yes -d 'Send DeleteProfile, then re-read the profile list and confirm. Without it nothing is changed: the profile and its consequence are printed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l confirm-eid -d 'The card\'s EID (32 hex digits); must match the EID read from the card' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l reader -d 'The reader to use, matched against the driver\'s own name' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l aid -d 'ISD-R AID as hex (default A0000005591010FFFFFFFF8900000100)' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l max-segment -d 'Most data bytes in one STORE DATA block, 1 to 255 (default 120, as lpac; 255 is the short-APDU Lc limit). Some eUICCs reject full 255-byte blocks' -r
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l operational -d 'Delete the operational profiles (resetOptions bit 0)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l test -d 'Delete the field-loaded test profiles (resetOptions bit 1)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l smdp-address -d 'Reset the default SM-DP+ address (resetOptions bit 2)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l yes -d 'Send the reset (needs `--confirm-eid`), then re-read and confirm. Without it nothing is changed: the profiles that would be erased are listed'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -l json -d 'Emit one lpac envelope on stdout, and nothing else'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from reset" -s h -l help -d 'Print help'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand euicc; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "modules" -d 'Describe the crate module roots and the layering between them'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "scan" -d 'Select a card\'s master file, walk everything under it, and report'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "ts48" -d 'Compare a card against the public GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "install" -d 'Write agent guidance (Claude skill, Cursor rule, AGENTS.md block) into a project'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "ci" -d 'Write the GitHub Actions workflow that runs this repo\'s action on pull requests'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "completions" -d 'Write a shell completion script to stdout'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "mcp" -d 'Serve the scan and the rules as MCP tools over stdio'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "rules" -d 'List the rules a scan runs, or explain one, without a card'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "why" -d 'Explain a rule, or every rule in a saved `scan --json` envelope'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "fix" -d 'Hand one finding from a saved scan to a coding agent'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "gp" -d 'Read-only GlobalPlatform queries'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "trace" -d 'Decode a captured APDU trace offline (no card, no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "fuzz" -d 'APDU discovery and the OTA/SMS fuzz sweep'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "euicc" -d 'eUICC queries over ES10 (lpac: chip info, profile list, notification list), and the profile and notification writes'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and not __fish_seen_subcommand_from modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ts48" -f -a "compare" -d 'Walk the card and diff its file system against the GSMA TS.48 test profile'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from ci" -f -a "install" -d 'Write .github/workflows/sim-doctor.yml, pinned to this version\'s tag'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "list" -d 'One row per rule: id, severity, summary'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from rules" -f -a "explain" -d 'What a rule means and how to fix it'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "info" -d 'Select the issuer security domain and read CPLC, card data, key information, IIN and CIN with GET DATA'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "ara" -d 'Select the ARA-M (Access Rule Application Master) and read every access rule with GET DATA [all], decoded (read-only, no keys)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "status" -d 'GlobalPlatform registry inventory: GET STATUS for the ISD, applications and load files, plus Card Recognition Data (read-only). A scope the card only gives over a secure channel is reported as requiring authentication'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "select" -d 'SELECT a GlobalPlatform (or any) application by AID and report the status word and the FCI. Read-only, no keys; it only changes the card\'s current selection'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "channel" -d 'Open or close a supplementary logical channel (MANAGE CHANNEL). A channel stays open on the card until it is closed or the card loses power, and the other gp commands can then run on it with --channel N'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "delete" -d 'Delete an application or an executable load file over an SCP03 channel (DELETE, GlobalPlatform Card Spec v2.3.1 11.2). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "install" -d 'Load a CAP file and install an applet over an SCP03 channel: INSTALL [for load], LOAD, INSTALL [for install and make selectable] (GlobalPlatform Card Spec v2.3.1 11.5, 11.6). CHANGES CARD CONTENT'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from gp" -f -a "put-key" -d 'Add or replace an SCP03 key set (ENC, MAC, DEK; AES-128) in the issuer security domain over an SCP03 channel (PUT KEY, GlobalPlatform Card Spec v2.3.1 11.8). CAN PERMANENTLY LOCK THE CARD\'S ADMINISTRATIVE ACCESS'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "apdu" -d 'CLA discovery (level 1) or CLA+INS discovery (level 2) over a session'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "ota" -d 'The OTA/SMS fuzz sweep: TAR x keyset x mechanism, built on the TAR scanner\'s ENVELOPE builder'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from fuzz" -f -a "mutate" -d 'Allowlist-only APDU mutation fuzzer, against a replay log or the built-in mock card only (no reader)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "info" -d 'EID, EUICCInfo1 and EUICCInfo2 (lpac `chip info`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "profiles" -d 'Installed profiles: ICCID, state, class, nickname, provider, name (lpac `profile list`)'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "notifications" -d 'Pending notification metadata (lpac `notification list`); `dump` and `replay` below; `notifications remove <seq>` removes one'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "nickname" -d 'Set a profile\'s nickname (lpac `profile nickname`). A write: a dry run unless `--yes`, never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "enable" -d 'Enable a profile (lpac `profile enable`, ES10c EnableProfile with REFRESH). A dry run unless `--yes`: switches the active profile and the device loses its connection until it re-attaches. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "disable" -d 'Disable a profile (lpac `profile disable`, ES10c DisableProfile with REFRESH). A dry run unless `--yes`: disabling the only enabled profile leaves no active profile. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "delete" -d 'Delete a profile (lpac `profile delete`, ES10c DeleteProfile). A dry run unless `--yes`: the profile is erased permanently and can only come back by downloading it again from the operator. An enabled profile is refused. Never exposed over MCP'
complete -c sim-doctor -n "__fish_sim_doctor_using_subcommand help; and __fish_seen_subcommand_from euicc" -f -a "reset" -d 'Reset the eUICC memory (lpac `chip purge`, ES10c eUICCMemoryReset). Can erase every profile: nothing is selected by default, and sending needs both `--yes` and `--confirm-eid <EID>` matching the card. Never exposed over MCP'
