#!/usr/bin/env bash
# Downloads the free GeoLite2 City database (no account or key needed) for the attack map.
# Data: MaxMind GeoLite2, licensed CC BY-SA 4.0 (mirror by wp-statistics). Attribution is in README.md.
set -e
DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/data/GeoLite2-City.mmdb}"
mkdir -p "$(dirname "$DEST")"
for URL in "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz" \
           "https://github.com/wp-statistics/GeoLite2-City/raw/master/GeoLite2-City.mmdb.gz"; do
  echo "Trying $URL"
  if curl -fL --retry 2 -o "$DEST.gz" "$URL"; then
    gunzip -f "$DEST.gz" && echo "Saved to $DEST" && exit 0
  fi
done
echo "Could not download the location database. Alerts still work; they just will not show a country or map point." >&2
exit 1
