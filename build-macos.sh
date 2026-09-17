#!/bin/bash
# verify-pades.mjs -> node суулгаагүй macOS дээр ажиллах standalone binary + .pkg
#
# Хэрэглээ:
#   ./build-macos.sh                 # build + sign (notarize алгасна)
#   ./build-macos.sh --notarize      # build + sign + notarize + staple
#
# Урьдчилсан нөхцөл (зөвхөн ЭНЭ build машин дээр):
#   - bun            : curl -fsSL https://bun.sh/install | bash
#   - Developer ID Application + Developer ID Installer гэрчилгээ keychain-д
#   - notarize хийх бол нэг удаа:
#       xcrun notarytool store-credentials verify-pades-notary \
#         --apple-id <apple-id> --team-id KSA54JY6J2 --password <app-specific-password>
set -euo pipefail
cd "$(dirname "$0")"

TEAM_ID="KSA54JY6J2"
APP_ID="Developer ID Application: Tridum e-Security LLC ($TEAM_ID)"
INSTALLER_ID="Developer ID Installer: Tridum e-Security LLC ($TEAM_ID)"
NOTARY_PROFILE="verify-pades-notary"
VERSION="$(node -p 'require("./package.json").version' 2>/dev/null || echo 1.0.0)"
NOTARIZE=0
[[ "${1:-}" == "--notarize" ]] && NOTARIZE=1

DIST="dist/macos"
rm -rf "$DIST" build/pkgroot
mkdir -p "$DIST" build/pkgroot/usr/local/bin build/pkgroot/usr/local/libexec/verify-pades

# 1. Хоёр архитектурт нэг нэг binary (bun runtime нь дотроо шигтгэгдэнэ).
for arch in arm64 x64; do
  echo "==> build darwin-$arch"
  bun build ./verify-pades.mjs --compile --minify \
    --target="bun-darwin-$arch" \
    --outfile "build/pkgroot/usr/local/libexec/verify-pades/verify-pades-$arch"
done

# 2. Gatekeeper: hardened runtime + JIT entitlement (bun-д JIT шаардлагатай).
cat > build/entitlements.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-jit</key><true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict>
</plist>
EOF

# 3. Архитектур сонгогч launcher — хэрэглэгч зөвхөн `verify-pades` гэж дуудна.
cat > build/pkgroot/usr/local/bin/verify-pades <<'EOF'
#!/bin/bash
# Intel дээр x64, Apple Silicon дээр arm64 binary-г дуудна (Rosetta шаардахгүй).
exec "/usr/local/libexec/verify-pades/verify-pades-$( [[ "$(uname -m)" == arm64 ]] && echo arm64 || echo x64 )" "$@"
EOF
chmod +x build/pkgroot/usr/local/bin/verify-pades

if security find-identity -v -p codesigning | grep -q "$APP_ID"; then
  for arch in arm64 x64; do
    codesign --force --timestamp --options runtime \
      --entitlements build/entitlements.plist \
      --sign "$APP_ID" "build/pkgroot/usr/local/libexec/verify-pades/verify-pades-$arch"
    codesign --verify --strict "build/pkgroot/usr/local/libexec/verify-pades/verify-pades-$arch"
  done
  SIGNED=1
else
  echo "!! '$APP_ID' олдсонгүй — гарын үсэггүй build. Өөр Mac дээр Gatekeeper блоклоно."
  SIGNED=0
fi

# 4. Binary-г тусад нь ч тараах боломжтой байлгана.
cp build/pkgroot/usr/local/libexec/verify-pades/verify-pades-arm64 "$DIST/"
cp build/pkgroot/usr/local/libexec/verify-pades/verify-pades-x64   "$DIST/"

# 5. .pkg — хэрэглэгч 2 дарж суулгаад ямар ч хавтаснаас `verify-pades` гэж ажиллуулна.
PKG="$DIST/verify-pades-$VERSION.pkg"
pkgbuild --root build/pkgroot --identifier mn.tridum.verify-pades \
  --version "$VERSION" --install-location / build/component.pkg >/dev/null
if [[ $SIGNED == 1 ]] && security find-identity -v | grep -q "$INSTALLER_ID"; then
  productbuild --package build/component.pkg --sign "$INSTALLER_ID" "$PKG" >/dev/null
else
  productbuild --package build/component.pkg "$PKG" >/dev/null
fi

# 6. Notarize — Apple-ээр баталгаажуулж, ticket-ийг .pkg дотор staple хийнэ.
#    Stapled .pkg нь интернэтгүй Mac дээр ч дуугүй нээгдэнэ.
if [[ $NOTARIZE == 1 ]]; then
  echo "==> notarize (хэдэн минут болно)"
  xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$PKG"
  xcrun stapler validate "$PKG"
fi

rm -rf build

# 7. install.sh нь татсан файлаа үүгээр шалгана — release-д ХАМТ нь байршуулна.
( cd "$DIST" && shasum -a 256 verify-pades-arm64 verify-pades-x64 "$(basename "$PKG")" > SHA256SUMS )

echo
echo "Бэлэн:"
ls -lh "$DIST"
echo
echo "GitHub release-д байршуулах (gh суулгасан бол):"
echo "  gh release create v$VERSION -R <ORG>/<REPO> $DIST/* --title v$VERSION --notes 'macOS build'"
