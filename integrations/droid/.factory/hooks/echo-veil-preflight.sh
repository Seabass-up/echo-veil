#!/bin/sh

mode=${1:-}
case "$mode" in
  prompt|agent) ;;
  *)
    printf '%s\n' 'Echo Veil required preflight could not start.' >&2
    exit 2
    ;;
esac

preflight_command=${ECHO_VEIL_PREFLIGHT_COMMAND:-}
if [ -z "$preflight_command" ]; then
  case "${HOME:-}" in
    /*) preflight_command="${HOME}/.local/bin/echo-veil-preflight-hook" ;;
    *) preflight_command= ;;
  esac
fi
case "$preflight_command" in
  /*) ;;
  *)
    printf '%s\n' 'Echo Veil required preflight is not configured.' >&2
    exit 2
    ;;
esac

if [ ! -x "$preflight_command" ]; then
  printf '%s\n' 'Echo Veil required preflight is unavailable.' >&2
  exit 2
fi

if "$preflight_command" --host droid --hook-mode "$mode"; then
  exit 0
fi

printf '%s\n' 'Echo Veil required preflight failed closed.' >&2
exit 2
