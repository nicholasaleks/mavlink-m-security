#!/bin/sh
# Regenerate military_dialect.py from the dialect source, if you have pymavlink
# with the generator (pip install pymavlink). The committed copy was generated
# from mavlink-military @ 6375c34; the exact pin does not affect the TARGET layout.
set -eu
XML="${1:?usage: generate_dialect.sh /path/to/military.xml}"
python3 -m pymavlink.tools.mavgen --lang=Python --wire-protocol=2.0 \
  --output="$(dirname "$0")/military_dialect" "$XML"
