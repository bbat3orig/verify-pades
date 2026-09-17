#!/bin/bash
# verify-pades — macOS дээр нэг мөрөөр суулгана. Node, bun, brew, gh шаардахгүй.
#
# Нээлттэй (public) repo:
#   curl -fsSL https://raw.githubusercontent.com/<ORG>/<REPO>/main/install.sh -o i.sh && bash i.sh
#
# Хаалттай (private) repo — токен хэрэгтэй:
#   GITHUB_TOKEN=ghp_xxx bash i.sh
#
# curl-аар татсан файлд macOS нь com.apple.quarantine тавьдаггүй тул
# Gatekeeper диалог гарахгүй, нэмэлт команд бичих шаардлагагүй.
set -euo pipefail

REPO="${VERIFY_PADES_REPO:-<ORG>/<REPO>}"
TAG="${VERIFY_PADES_TAG:-latest}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
ARCH="$([[ "$(uname -m)" == arm64 ]] && echo arm64 || echo x64)"
ASSET="verify-pades-$ARCH"

die() { echo "!! $*" >&2; exit 1; }

# --- татах зам: токентой бол API (private-д ажиллана), эс бол шууд линк -------
if [[ -n "$TOKEN" ]]; then
  api() { curl -fsSL -H "Authorization: Bearer $TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" "$@"; }
  REL_URL="https://api.github.com/repos/$REPO/releases/$([[ "$TAG" == latest ]] && echo latest || echo "tags/$TAG")"
  JSON="$(api -H "Accept: application/vnd.github+json" "$REL_URL")" \
    || die "Release олдсонгүй: $REPO@$TAG (токен зөв эсэхийг шалгана уу)"
  # grep-ийн загварууд зайгүй JSON гэж үзнэ — форматлагдсан хариу ирж ч болзошгүй.
  JSON="$(tr -d ' \n' <<<"$JSON")"

  # Asset бүр нэг JSON объект. "id" ба "name" нь "uploader" гэсэн үүрлэсэн
  # объектоос ӨМНӨ ирдэг тул '{'-ээр хуваахад хоёул нэг хэсэгт үлдэнэ.
  fetch() { # $1=asset нэр, $2=гаралт. Олдохгүй бол ҮХЭХГҮЙ, төлөв буцаана.
    local id
    id="$(tr '{' '\n' <<<"$JSON" \
          | grep -F "\"name\":\"$1\"" \
          | grep -o '"id":[0-9]*' | head -1 | tr -dc '0-9')"
    [[ -n "$id" ]] || return 1
    api -H "Accept: application/octet-stream" \
      "https://api.github.com/repos/$REPO/releases/assets/$id" -o "$2"
  }
else
  BASE="https://github.com/$REPO/releases/$([[ "$TAG" == latest ]] && echo latest/download || echo "download/$TAG")"
  fetch() { curl -fsSL "$BASE/$1" -o "$2"; }
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "==> Татаж байна: $REPO@$TAG / $ASSET"
fetch "$ASSET" "$TMP/$ASSET" \
  || die "Татаж чадсангүй: $REPO@$TAG / $ASSET (private repo бол GITHUB_TOKEN өгнө үү)"

# --- бүрэн бүтэн эсэхийг шалгах ------------------------------------------------
if fetch SHA256SUMS "$TMP/SHA256SUMS" 2>/dev/null; then
  ( cd "$TMP" && grep -F " $ASSET" SHA256SUMS | shasum -a 256 -c - >/dev/null ) \
    || die "SHA-256 таарсангүй — татсан файлыг бүү ашигла."
  echo "==> SHA-256 таарлаа"
else
  echo "!! SHA256SUMS алга — checksum шалгалт алгаслаа."
fi

# Гарын үсгийг нь бас шалгана (Developer ID: Tridum e-Security LLC).
if codesign --verify --strict "$TMP/$ASSET" 2>/dev/null; then
  echo "==> Гарын үсэг: $(codesign -dv --verbose=2 "$TMP/$ASSET" 2>&1 | sed -n 's/^Authority=//p' | head -1)"
else
  echo "!! Гарын үсэг баталгаажсангүй."
fi

# --- суулгах -------------------------------------------------------------------
if mkdir -p /usr/local/bin 2>/dev/null && [[ -w /usr/local/bin ]]; then
  DEST=/usr/local/bin
else
  DEST="$HOME/.local/bin"
  mkdir -p "$DEST"
fi
chmod +x "$TMP/$ASSET"
mv -f "$TMP/$ASSET" "$DEST/verify-pades"

echo "==> Суулаа: $DEST/verify-pades"
case ":$PATH:" in
  *":$DEST:"*)
    echo "==> Хэрэглээ:  verify-pades гэрээ.pdf --online"
    ;;
  *)
    echo "!! $DEST нь PATH-д алга. Нэмэх:"
    echo "   echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
    ;;
esac
