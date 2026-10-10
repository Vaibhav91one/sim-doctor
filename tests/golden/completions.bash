_sim__doctor() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="sim__doctor"
                ;;
            sim__doctor,card)
                cmd="sim__doctor__subcmd__card"
                ;;
            sim__doctor,ci)
                cmd="sim__doctor__subcmd__ci"
                ;;
            sim__doctor,completions)
                cmd="sim__doctor__subcmd__completions"
                ;;
            sim__doctor,euicc)
                cmd="sim__doctor__subcmd__euicc"
                ;;
            sim__doctor,fix)
                cmd="sim__doctor__subcmd__fix"
                ;;
            sim__doctor,fuzz)
                cmd="sim__doctor__subcmd__fuzz"
                ;;
            sim__doctor,gp)
                cmd="sim__doctor__subcmd__gp"
                ;;
            sim__doctor,help)
                cmd="sim__doctor__subcmd__help"
                ;;
            sim__doctor,install)
                cmd="sim__doctor__subcmd__install"
                ;;
            sim__doctor,mcp)
                cmd="sim__doctor__subcmd__mcp"
                ;;
            sim__doctor,modules)
                cmd="sim__doctor__subcmd__modules"
                ;;
            sim__doctor,rules)
                cmd="sim__doctor__subcmd__rules"
                ;;
            sim__doctor,scan)
                cmd="sim__doctor__subcmd__scan"
                ;;
            sim__doctor,trace)
                cmd="sim__doctor__subcmd__trace"
                ;;
            sim__doctor,ts48)
                cmd="sim__doctor__subcmd__ts48"
                ;;
            sim__doctor,why)
                cmd="sim__doctor__subcmd__why"
                ;;
            sim__doctor__subcmd__ci,help)
                cmd="sim__doctor__subcmd__ci__subcmd__help"
                ;;
            sim__doctor__subcmd__ci,install)
                cmd="sim__doctor__subcmd__ci__subcmd__install"
                ;;
            sim__doctor__subcmd__ci__subcmd__help,help)
                cmd="sim__doctor__subcmd__ci__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ci__subcmd__help,install)
                cmd="sim__doctor__subcmd__ci__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__euicc,delete)
                cmd="sim__doctor__subcmd__euicc__subcmd__delete"
                ;;
            sim__doctor__subcmd__euicc,disable)
                cmd="sim__doctor__subcmd__euicc__subcmd__disable"
                ;;
            sim__doctor__subcmd__euicc,enable)
                cmd="sim__doctor__subcmd__euicc__subcmd__enable"
                ;;
            sim__doctor__subcmd__euicc,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc,info)
                cmd="sim__doctor__subcmd__euicc__subcmd__info"
                ;;
            sim__doctor__subcmd__euicc,nickname)
                cmd="sim__doctor__subcmd__euicc__subcmd__nickname"
                ;;
            sim__doctor__subcmd__euicc,notifications)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications"
                ;;
            sim__doctor__subcmd__euicc,profiles)
                cmd="sim__doctor__subcmd__euicc__subcmd__profiles"
                ;;
            sim__doctor__subcmd__euicc,reset)
                cmd="sim__doctor__subcmd__euicc__subcmd__reset"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,delete)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__delete"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,disable)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__disable"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,enable)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__enable"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,info)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__info"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,nickname)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__nickname"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,notifications)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,profiles)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__profiles"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,reset)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__reset"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay"
                ;;
            sim__doctor__subcmd__fuzz,apdu)
                cmd="sim__doctor__subcmd__fuzz__subcmd__apdu"
                ;;
            sim__doctor__subcmd__fuzz,help)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help"
                ;;
            sim__doctor__subcmd__fuzz,mutate)
                cmd="sim__doctor__subcmd__fuzz__subcmd__mutate"
                ;;
            sim__doctor__subcmd__fuzz,ota)
                cmd="sim__doctor__subcmd__fuzz__subcmd__ota"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,apdu)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__apdu"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,help)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,mutate)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__mutate"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,ota)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__ota"
                ;;
            sim__doctor__subcmd__gp,ara)
                cmd="sim__doctor__subcmd__gp__subcmd__ara"
                ;;
            sim__doctor__subcmd__gp,channel)
                cmd="sim__doctor__subcmd__gp__subcmd__channel"
                ;;
            sim__doctor__subcmd__gp,delete)
                cmd="sim__doctor__subcmd__gp__subcmd__delete"
                ;;
            sim__doctor__subcmd__gp,help)
                cmd="sim__doctor__subcmd__gp__subcmd__help"
                ;;
            sim__doctor__subcmd__gp,info)
                cmd="sim__doctor__subcmd__gp__subcmd__info"
                ;;
            sim__doctor__subcmd__gp,install)
                cmd="sim__doctor__subcmd__gp__subcmd__install"
                ;;
            sim__doctor__subcmd__gp,put-key)
                cmd="sim__doctor__subcmd__gp__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__gp,select)
                cmd="sim__doctor__subcmd__gp__subcmd__select"
                ;;
            sim__doctor__subcmd__gp,status)
                cmd="sim__doctor__subcmd__gp__subcmd__status"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,close)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,help)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,open)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,close)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,open)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,ara)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__ara"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,channel)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,delete)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__delete"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,info)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__info"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,install)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,put-key)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,select)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__select"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,status)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__status"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__channel,close)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__channel,open)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__help,card)
                cmd="sim__doctor__subcmd__help__subcmd__card"
                ;;
            sim__doctor__subcmd__help,ci)
                cmd="sim__doctor__subcmd__help__subcmd__ci"
                ;;
            sim__doctor__subcmd__help,completions)
                cmd="sim__doctor__subcmd__help__subcmd__completions"
                ;;
            sim__doctor__subcmd__help,euicc)
                cmd="sim__doctor__subcmd__help__subcmd__euicc"
                ;;
            sim__doctor__subcmd__help,fix)
                cmd="sim__doctor__subcmd__help__subcmd__fix"
                ;;
            sim__doctor__subcmd__help,fuzz)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz"
                ;;
            sim__doctor__subcmd__help,gp)
                cmd="sim__doctor__subcmd__help__subcmd__gp"
                ;;
            sim__doctor__subcmd__help,help)
                cmd="sim__doctor__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__help,install)
                cmd="sim__doctor__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__help,mcp)
                cmd="sim__doctor__subcmd__help__subcmd__mcp"
                ;;
            sim__doctor__subcmd__help,modules)
                cmd="sim__doctor__subcmd__help__subcmd__modules"
                ;;
            sim__doctor__subcmd__help,rules)
                cmd="sim__doctor__subcmd__help__subcmd__rules"
                ;;
            sim__doctor__subcmd__help,scan)
                cmd="sim__doctor__subcmd__help__subcmd__scan"
                ;;
            sim__doctor__subcmd__help,trace)
                cmd="sim__doctor__subcmd__help__subcmd__trace"
                ;;
            sim__doctor__subcmd__help,ts48)
                cmd="sim__doctor__subcmd__help__subcmd__ts48"
                ;;
            sim__doctor__subcmd__help,why)
                cmd="sim__doctor__subcmd__help__subcmd__why"
                ;;
            sim__doctor__subcmd__help__subcmd__ci,install)
                cmd="sim__doctor__subcmd__help__subcmd__ci__subcmd__install"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,delete)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__delete"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,disable)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__disable"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,enable)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__enable"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,info)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__info"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,nickname)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__nickname"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,notifications)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,profiles)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__profiles"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,reset)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__reset"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,apdu)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__apdu"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,mutate)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__mutate"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,ota)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__ota"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,ara)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__ara"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,channel)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,delete)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__delete"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,info)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__info"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,install)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__install"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,put-key)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,select)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__select"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,status)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__status"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__channel,close)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__channel,open)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__help__subcmd__rules,explain)
                cmd="sim__doctor__subcmd__help__subcmd__rules__subcmd__explain"
                ;;
            sim__doctor__subcmd__help__subcmd__rules,list)
                cmd="sim__doctor__subcmd__help__subcmd__rules__subcmd__list"
                ;;
            sim__doctor__subcmd__help__subcmd__ts48,compare)
                cmd="sim__doctor__subcmd__help__subcmd__ts48__subcmd__compare"
                ;;
            sim__doctor__subcmd__rules,explain)
                cmd="sim__doctor__subcmd__rules__subcmd__explain"
                ;;
            sim__doctor__subcmd__rules,help)
                cmd="sim__doctor__subcmd__rules__subcmd__help"
                ;;
            sim__doctor__subcmd__rules,list)
                cmd="sim__doctor__subcmd__rules__subcmd__list"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,explain)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__explain"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,help)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,list)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__list"
                ;;
            sim__doctor__subcmd__ts48,compare)
                cmd="sim__doctor__subcmd__ts48__subcmd__compare"
                ;;
            sim__doctor__subcmd__ts48,help)
                cmd="sim__doctor__subcmd__ts48__subcmd__help"
                ;;
            sim__doctor__subcmd__ts48__subcmd__help,compare)
                cmd="sim__doctor__subcmd__ts48__subcmd__help__subcmd__compare"
                ;;
            sim__doctor__subcmd__ts48__subcmd__help,help)
                cmd="sim__doctor__subcmd__ts48__subcmd__help__subcmd__help"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        sim__doctor)
            opts="-h -V --help --version modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc card help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__card)
            opts="-c -h --reader --profile --dialect --script --json --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -W "uicc sim" -- "${cur}"))
                    return 0
                    ;;
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --script)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci)
            opts="-h --help install help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help)
            opts="install help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__install)
            opts="-h --swsim --baseline --require-baseline --severity --ref --dir --force --print-only --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --swsim)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --require-baseline)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --severity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ref)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__completions)
            opts="-h --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc)
            opts="-h --help info profiles notifications nickname enable disable delete reset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__delete)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__disable)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__enable)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help)
            opts="info profiles notifications nickname enable disable delete reset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__nickname)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications)
            opts="remove dump replay"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__profiles)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__info)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__nickname)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications)
            opts="-h --reader --json --aid --max-segment --help remove dump replay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__dump)
            opts="-o -h --seq --output --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --seq)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help)
            opts="remove dump replay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__remove)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__replay)
            opts="-h --from --yes --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__profiles)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__reset)
            opts="-h --operational --test --smdp-address --confirm-eid --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --confirm-eid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fix)
            opts="-h --from --agent --skip-approvals --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --agent)
                    COMPREPLY=($(compgen -W "claude codex cursor" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz)
            opts="-h --help apdu ota mutate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__apdu)
            opts="-h --i-understand-this-can-brick-the-card --allow-real-hardware --reader --json --quick --level --class --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --class)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help)
            opts="apdu ota mutate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__mutate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__ota)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__mutate)
            opts="-h --replay --mock --max-cases --timeout --seed --dry-run --stop-on-first-finding --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --replay)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-cases)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --seed)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__ota)
            opts="-h --i-understand-this-can-brick-the-card --allow-real-hardware --reader --json --quick --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp)
            opts="-h --help info ara status select channel delete install put-key help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__ara)
            opts="-h --reader --json --trace --channel --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel)
            opts="-h --help open close help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__close)
            opts="-h --channel --reader --json --trace --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help)
            opts="open close help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__open)
            opts="-h --reader --json --trace --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__delete)
            opts="-h --aid --related --reader --json --trace --keys-file --keys-env --key-version --channel --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help)
            opts="info ara status select channel delete install put-key help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__ara)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel)
            opts="open close"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__put__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__select)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__info)
            opts="-h --reader --json --trace --channel --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__install)
            opts="-h --load --module --app --params --privileges --dap-key-file --dap-key-env --dap-sd --dap-hash --reader --json --trace --keys-file --keys-env --key-version --channel --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --load)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --module)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --app)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --params)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --privileges)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-sd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-hash)
                    COMPREPLY=($(compgen -W "sha256 sha384 sha512" -- "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__put__subcmd__key)
            opts="-h --new-key-version --replace-key-version --key-id --new-keys-file --new-keys-env --replace-current-keyset --reader --json --trace --keys-file --keys-env --key-version --channel --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --new-key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --replace-key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__select)
            opts="-h --aid --reader --json --trace --channel --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__status)
            opts="-h --reader --json --trace --channel --keys-file --keys-env --key-version --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help)
            opts="modules scan ts48 install ci completions mcp rules why fix gp trace fuzz euicc card help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__card)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ci)
            opts="install"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ci__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc)
            opts="info profiles notifications nickname enable disable delete reset"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__nickname)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications)
            opts="remove dump replay"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__profiles)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz)
            opts="apdu ota mutate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__mutate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__ota)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp)
            opts="info ara status select channel delete install put-key"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__ara)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel)
            opts="open close"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__put__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__select)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__mcp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__modules)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules)
            opts="list explain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__trace)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ts48)
            opts="compare"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ts48__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__why)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__install)
            opts="-h --agent --print-only --dir --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --agent)
                    COMPREPLY=($(compgen -W "claude cursor codex opencode" -- "${cur}"))
                    return 0
                    ;;
                --dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__mcp)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__modules)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules)
            opts="-h --help list explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__explain)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help)
            opts="list explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__list)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__scan)
            opts="-h --json --tui --dialect --reader --max-depth --max-children --max-nodes --max-directories --score --severity --baseline --fail-on --sarif --tar --terminal-profile --face --theme --color --headless --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-children)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-nodes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-directories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sarif)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --tar)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --face)
                    COMPREPLY=($(compgen -W "rich plain compact legacy" -- "${cur}"))
                    return 0
                    ;;
                --theme)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__trace)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48)
            opts="-h --help compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__compare)
            opts="-h --json --reader --dialect --max-depth --max-children --max-nodes --max-directories --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-children)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-nodes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-directories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help)
            opts="compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__why)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _sim__doctor -o nosort -o bashdefault -o default sim-doctor
else
    complete -F _sim__doctor -o bashdefault -o default sim-doctor
fi
