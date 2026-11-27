# Sourced by the scripts. Calls the 3x-ui API of $panel with $XUI_API_TOKEN and prints the answer's obj,
# failing when the panel answers success: false. Extra curl arguments go after the path.
api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "$method" -H "Authorization: Bearer $XUI_API_TOKEN" "$panel/panel/api/$path" "$@" |
    jq -c 'if .success then .obj else error(.msg) end'
}
