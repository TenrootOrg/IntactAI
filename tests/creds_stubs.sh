#!/bin/bash
# Fake tools for the credential suites (test_upgrade_creds.sh,
# test_apply_passwords.sh): `docker` and `curl` executables on PATH that behave
# like the real tools where a password is concerned, with their state in files
# under $T so a test can set it up and assert on it:
#
#   running / exists   containers running / present but stopped (one per line)
#   volumes            named volumes present
#   calls              every docker/curl call (curl without its credentials)
#   argv               every curl argv in full: no value or JWT may be in it
#   velo_db / velo_live  Velociraptor users "user:password" in the datastore /
#                      loaded by the RUNNING server. `user add` (value from the
#                      exec's env, $_P) writes velo_db; only a compose recreate
#                      copies it to velo_live (0.77.3: a running server does not
#                      see `user add`). The recreate also plays the entrypoint:
#                      a stored value whose sha256 is not the stamp in
#                      data/velociraptor goes into velo_db first.
#   es_pw kib_pw       the `elastic` / `kibana_system` password the cluster
#                      accepts; an elk recreate (its setup container) sets
#                      kib_pw from the store when the stored elastic one works
#   ts_pw iris_pw vw_pw  the Timesketch / IRIS / VolWeb admin password
#   pt_pw pt_gen       the Portainer admin password (user admin, Id 3); a JWT
#                      is "J<pt_gen>" and dies when the password changes
#   *_rc / *_refuse    make one step fail: velo_rc ts_rc vw_rc compose_rc
#                      restart_rc es_refuse pt_refuse pt_back_refuse (refuse a
#                      PUT whose NewPassword is the one in pt_back_refuse)
#   compose_fails      the next N compose calls fail (a recreate of
#                      velociraptor that fails leaves it stopped)
#   A docker exec into a container not in `running` fails, like the real one.
# Not a test file (no test_ prefix): sourced by the two suites.

creds_stubs() {
    local T="$1"
    mkdir -p "$T/bin"
    : > "$T/running"; : > "$T/exists"; : > "$T/volumes"; : > "$T/calls"; : > "$T/argv"
    : > "$T/velo_db"; : > "$T/velo_live"; : > "$T/iris_pw"
    cat > "$T/bin/docker" <<EOF
#!/bin/bash
T="$T"
EOF
    cat >> "$T/bin/docker" <<'EOF'
echo "docker $*" >> "$T/calls"
rc() { exit "$(cat "$T/$1" 2>/dev/null || echo 0)"; }
case "$1" in
    info) exit 0 ;;
    volume) grep -qx "$3" "$T/volumes" ;;
    ps) n="$(sed -n 's/.*name=^\([^$]*\)\$.*/\1/p' <<<"$*")"; grep -x "$n" "$T/running"; exit 0 ;;
    inspect)
        if [[ "$2" == -f ]]; then
            grep -qx "$4" "$T/running" && { echo true; exit 0; }
            grep -qx "$4" "$T/exists" && { echo false; exit 0; }
            exit 1
        fi
        grep -qx "$2" "$T/running" || grep -qx "$2" "$T/exists" ;;
    restart) rc restart_rc ;;
    compose)
        echo "compose $(basename "$PWD") ${*:2}" >> "$T/calls"
        m="$(basename "$PWD")"
        r="$(cat "$T/compose_rc" 2>/dev/null || echo 0)"
        n="$(cat "$T/compose_fails" 2>/dev/null || echo 0)"
        (( n > 0 )) && { echo $(( n - 1 )) > "$T/compose_fails"; r=1; }
        if (( r )); then
            [[ "$m" == velociraptor ]] && sed -i '/^intact_velociraptor$/d' "$T/running"
            exit "$r"
        fi
        [[ " $* " == *" up "* ]] || exit 0
        if [[ "$m" == velociraptor ]]; then
            d="$PWD/../../data/velociraptor"; mkdir -p "$d"
            ep() {   # KEY stamp user -- the entrypoint's stamp logic
                local v sum; v="$(sed -n "s/^$1=//p" secrets/creds.env 2>/dev/null | tail -1)"; [[ -n "$v" ]] || return 0
                sum="$(printf '%s' "$v" | sha256sum | cut -d' ' -f1)"
                [[ "$(cat "$d/$2" 2>/dev/null)" == "$sum" ]] && grep -q "^$3:" "$T/velo_db" && return 0
                { grep -v "^$3:" "$T/velo_db"; echo "$3:$v"; } > "$T/velo_db.n"; mv "$T/velo_db.n" "$T/velo_db"
                echo "$sum" > "$d/$2"
            }
            gu="$(sed -n 's/^VELOX_USER=//p' .env | tail -1)"; au="$(sed -n 's/^VELOX_USER_2=//p' .env | tail -1)"
            ep VELOX_PASSWORD .gui_pw.sha256 "${gu:-tenroot}"; ep VELOX_PASSWORD_2 .api_pw.sha256 "${au:-api}"
            cp "$T/velo_db" "$T/velo_live"
            grep -qx intact_velociraptor "$T/running" || echo intact_velociraptor >> "$T/running"
        elif [[ "$m" == elk ]]; then
            e="$(sed -n 's/^ELASTIC_PASSWORD=//p' secrets/creds.env 2>/dev/null)"; k="$(sed -n 's/^KIBANA_PASSWORD=//p' secrets/creds.env 2>/dev/null)"
            [[ -n "$k" && "$e" == "$(cat "$T/es_pw" 2>/dev/null)" ]] && printf '%s' "$k" > "$T/kib_pw"
        fi
        exit 0 ;;
    exec)
        set -- "${@:2}"
        while [[ "$1" == -* ]]; do case "$1" in -e|-w|-u|--user) shift 2 ;; *) shift ;; esac; done
        grep -qx "$1" "$T/running" || exit 1
        case "$*" in
            *"user add"*)
                r="$(cat "$T/velo_rc" 2>/dev/null || echo 0)"; (( r )) && exit "$r"
                u="${@: -2:1}"
                { grep -v "^$u:" "$T/velo_db"; echo "$u:$_P"; } > "$T/velo_db.n"; mv "$T/velo_db.n" "$T/velo_db" ;;
            *intact_iris_db*SELECT*) [[ -s "$T/iris_pw" ]] && echo '$2b$12$fakehash' ;;
            *intact_iris_db*UPDATE*)
                p="$(sed -n "s/.*password='\$2b\$12\$H:\([^']*\)'.*/\1/p" <<<"$*")"
                printf '%s' "$p" > "$T/iris_pw"; echo "UPDATE 1" ;;
            *intact_iris_app*generate_password_hash*) echo "\$2b\$12\$H:$(cat)" ;;
            *intact_iris_app*) [[ -s "$T/iris_pw" && "$_IRIS_PW" == "$(cat "$T/iris_pw")" ]] ;;
            *intact_timesketch_postgres*SELECT*) [[ -s "$T/ts_pw" ]] && echo '$2b$12$fakehash' ;;
            *intact_timesketch_web*tsctl*)
                read -r a; read -r b
                r="$(cat "$T/ts_rc" 2>/dev/null || echo 0)"; (( r )) && exit "$r"
                [[ "$a" == "$b" ]] && printf '%s' "$a" > "$T/ts_pw" ;;
            *intact_timesketch_web*python3*) [[ "$_TS_PW" == "$(cat "$T/ts_pw" 2>/dev/null)" ]] ;;
            *intact_volweb_backend*"shell -c"*)
                [[ "$_VW_PW" == "$(cat "$T/vw_pw" 2>/dev/null)" ]] && echo PW-OK || echo PW-NO ;;
            *intact_volweb_backend*shell*)
                p="$(sed -n "s/^u.set_password('\(.*\)')$/\1/p")"
                r="$(cat "$T/vw_rc" 2>/dev/null || echo 0)"; (( r )) && exit "$r"
                printf '%s' "$p" > "$T/vw_pw"; echo "UPDATED admin" ;;
        esac ;;
esac
EOF
    cat > "$T/bin/curl" <<EOF
#!/bin/bash
T="$T"
EOF
    cat >> "$T/bin/curl" <<'EOF'
a=("$@"); cfg="" method=GET body="" url="${*: -1}"
for (( i = 0; i < ${#a[@]}; i++ )); do
    case "${a[$i]}" in -K) cfg="${a[$((i+1))]}" ;; -X) method="${a[$((i+1))]}" ;; esac
done
echo "curl $*" >> "$T/argv"
cred=""
if [[ "$cfg" == - ]]; then cred="$(cat)"; elif [[ -n "$cfg" ]]; then cred="$(cat "$cfg")"; fi
jwt="$(sed -n 's/^header = "Authorization: Bearer \(.*\)"$/\1/p' <<<"$cred")"
# curl's config quoting, undone: \" -> "  and  \\ -> \ .
cred="$(python3 -c 'import re,sys; m=re.match(r"user = \"(.*)\"$", sys.stdin.read().strip()); print(re.sub(r"\\(.)", r"\1", m.group(1)) if m else "")' <<<"$cred")"
[[ " $* " == *" --data-binary @- "* ]] && body="$(cat)"
echo "curl $method $url" >> "$T/calls"
js() { python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2],""))' "$body" "$1"; }
gen="$(cat "$T/pt_gen" 2>/dev/null || echo 0)"
case "$method $url" in
    *:8889/*)
        grep -qx intact_velociraptor "$T/running" || { echo 000; exit 0; }
        grep -qxF -- "$cred" "$T/velo_live" && echo 200 || echo 401 ;;
    *:9200/_security/_authenticate)
        if [[ -s "$T/es_pw" && "$cred" == "elastic:$(cat "$T/es_pw")" ]] \
            || [[ -s "$T/kib_pw" && "$cred" == "kibana_system:$(cat "$T/kib_pw")" ]]; then echo 200; else echo 401; fi ;;
    "POST "*:9200/_security/user/elastic/_password)
        if [[ ! -e "$T/es_refuse" && "$cred" == "elastic:$(cat "$T/es_pw")" ]]; then js password > "$T/es_pw.n"; mv "$T/es_pw.n" "$T/es_pw"; echo 200
        else echo 401; fi ;;
    "POST https://127.0.0.1:9443/api/auth")
        [[ "$(js Password)" == "$(cat "$T/pt_pw" 2>/dev/null)" ]] && printf '{"jwt":"J%s"}\n200' "$gen" || printf '{}\n422' ;;
    "GET https://127.0.0.1:9443/api/users")
        [[ "$jwt" == "J$gen" ]] || { printf '{}\n401'; exit 0; }
        printf '[{"Id":1,"Username":"other"},{"Id":3,"Username":"admin"}]\n200' ;;
    "PUT https://127.0.0.1:9443/api/users/3/passwd")
        if [[ "$jwt" != "J$gen" ]]; then printf '{}\n401'
        elif [[ -e "$T/pt_refuse" || "$(js Password)" != "$(cat "$T/pt_pw")" ]]; then printf '{}\n400'
        elif [[ -s "$T/pt_back_refuse" && "$(js NewPassword)" == "$(cat "$T/pt_back_refuse")" ]]; then printf '{}\n400'
        else js NewPassword > "$T/pt_pw"; echo $(( gen + 1 )) > "$T/pt_gen"; printf '\n204'; fi ;;
    *) echo 000 ;;
esac
exit 0
EOF
    chmod +x "$T/bin/docker" "$T/bin/curl"
}
