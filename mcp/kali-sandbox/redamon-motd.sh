# Printed after the standard Kali MOTD on every login shell, so users see the
# redagraph hint without cluttering the webapp banner.
printf '\n'
printf '\033[1;33m  \xe2\x9a\xa1 redagraph\033[0m \033[2;37m\xe2\x80\x94 tenant-scoped graph CLI\033[0m\n'
printf '  \033[2;37mExample:\033[0m \033[1;32mredagraph ask list CVEs with cve_id severity cvss > cves.txt\033[0m\n'
printf '  \033[2;37mFor more info:\033[0m \033[1;32mredagraph -h\033[0m\n'
printf '\n'
# The orchestrator sets MSF_REVERSE_PORT to this sandbox's pool port, the one port
# targets reach directly, or to 4444 when it has none: 4444 is reached only through
# a tunnel the person runs. Sourced into the login shell, so its variable is unset.
_redamon_lport="${MSF_REVERSE_PORT:-4444}"
case "$_redamon_lport" in
    ''|*[!0-9]*) _redamon_lport=4444 ;;
esac
if [ "$_redamon_lport" != 4444 ]; then
    printf '  \033[1;33mYour reverse-shell port (LPORT): %s\033[0m\n' "$_redamon_lport"
    printf '  \033[2;37mThe one port targets reach in this sandbox once the operator has opened it, shared by all of your chats; Metasploit uses it by default.\033[0m\n'
else
    printf '  \033[1;33mNo reverse-shell port is published for this sandbox.\033[0m\n'
    printf '  \033[2;37mA reverse shell needs your own tunnel (ngrok or chisel, which reach port 4444 here), or use a bind payload.\033[0m\n'
fi
printf '\n'
unset _redamon_lport
