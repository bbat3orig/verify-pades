/**
 * Бие даасан PDF/CMS шалгагч.
 * Хэрэглээ: node tools/verify-pades.mjs "гэрээ.pdf" */
import { createHash, webcrypto, X509Certificate } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  PDFDocument,
  PDFSignature,
  PDFDict,
  PDFArray,
  PDFNumber,
  PDFName,
  PDFHexString,
  PDFString,
} from "pdf-lib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

/**
 * Цуцлалтын online шалгалт — `--online`-ын цорын ганц хэрэгжүүлэлт.
 *
 * ⚠ Энэ файлд `checkRevocation`-ыг ХУУЛЖ БИЧИХГҮЙ. 2026-09-17-нд тэр хуулбар энд
 *   байсан боловч туслах функцууд нь дагаагүй тул `--online` зам эхний дуудлагадаа
 *   `ReferenceError: certificateUrls is not defined` өгч цуцлалтыг `unknown` болгож байв.
 *   Алдаа нь catch-д баригдаж `reason` болдог тул ЧИМЭЭГҮЙ байсан — цуцалсан
 *   гэрчилгээг "тодорхойгүй" гэж тайлагнах эрсдэлтэй.
 */

export async function checkRevocation(leaf, candidates, { allowPrivateNetwork = false, now = new Date(), timeoutMs = 10_000, maxBytes = 8 * 1024 * 1024 } = {}) {
  const report = { status: 'unknown', scope: 'signer-certificate-now', checkedAt: now.toISOString(), attempts: [] };
  const deadline = Date.now() + 45_000;
  const fetchBytes = (url, body) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) fail('revocation-time-budget');
    return download(url, { body, allowPrivateNetwork, timeoutMs: Math.min(timeoutMs, remaining), maxBytes });
  };
  try {
    const urls = certificateUrls(leaf); report.urls = urls;
    let issuer = candidates.find((candidate) => candidate instanceof pkijs.Certificate && issuedBy(leaf, candidate));
    if (!issuer) {
      for (const url of urls.caIssuers) {
        try {
          const found = issuerCertificates(await fetchBytes(url)).find((candidate) => issuedBy(leaf, candidate));
          if (!found) fail('ca-issuers-certificate-mismatch');
          issuer = found; candidates.push(found);
          report.attempts.push({ source: 'caIssuers', url, status: 'issuer-found' }); break;
        } catch (error) { report.attempts.push({ source: 'caIssuers', url, status: 'unknown', reason: error.message }); }
      }
    }
    if (!issuer) fail('issuer-certificate-missing');
    report.issuerFingerprint = fingerprint(issuer);
    if (!current(issuer, now)) fail('issuer-certificate-not-current');
    for (const source of ['ocsp', 'crl']) {
      for (const url of urls[source]) {
        try {
          let outcome;
          if (source === 'ocsp') {
            const request = new pkijs.OCSPRequest();
            await request.createForCertificate(leaf, { hashAlgorithm: 'SHA-1', issuerCertificate: issuer });
            const nonce = randomBytes(32);
            request.tbsRequest.requestExtensions = [new pkijs.Extension({ extnID: OID.nonce,
              extnValue: new asn1js.OctetString({ valueHex: nonce }).toBER(false) })];
            outcome = await verifyOcsp(await fetchBytes(url, Buffer.from(request.toSchema(true).toBER(false))), leaf, issuer, nonce, now);
          } else outcome = await verifyCrl(await fetchBytes(url), leaf, issuer, now);
          report.attempts.push({ ...outcome, url });
          if (outcome.status !== 'unknown') return { ...report, ...outcome, url };
        } catch (error) { report.attempts.push({ source, url, status: 'unknown', reason: error.message }); }
      }
    }
    report.reason = urls.ocsp.length || urls.crl.length ? 'no-conclusive-response' : 'no-supported-revocation-url';
  } catch (error) { report.reason = error.message; }
  return report;
}

pkijs.setEngine(
  "node",
  new pkijs.CryptoEngine({
    name: "node",
    crypto: webcrypto,
    subtle: webcrypto.subtle,
  }),
);
const OID = {
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  contentType: "1.2.840.113549.1.9.3",
  digest: "1.2.840.113549.1.9.4",
  ess: "1.2.840.113549.1.9.16.2.12",
  essV2: "1.2.840.113549.1.9.16.2.47",
  timestamp: "1.2.840.113549.1.9.16.2.14",
};
const HASHES = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};
/**
 * Тайлангийн сүүлчийн хэсэг — ЮУ ШАЛГАГДААГҮЙ бэ.
 *
 * ⚠ Эдгээр нь чимэх биш. `integrity-valid` гэснийг "баримт хүчинтэй"
 *   гэж унших нь энэ шалгагчийг буруу хэрэглэх цорын ганц зам. Тиймээс мөр бүр ШАЛГААГҮЙ
 *   ЗҮЙЛИЙГ нэрлээд, түүний УЧИР ХОЛБОГДЛыг хэлнэ.
 */
const buffer = (value) => Buffer.from(value);
const hash = (algorithm, value) => createHash(algorithm).update(value).digest();
const fail = (message) => {
  throw new Error(message);
};
const name = (dict, key) =>
  dict.lookupMaybe(PDFName.of(key), PDFName)?.decodeText() ?? null;
const string = (dict, key) => {
  const value = dict.lookup(PDFName.of(key));
  return value instanceof PDFString || value instanceof PDFHexString
    ? value.decodeText()
    : null;
};
function fields(document) {
  return document
    .getForm()
    .getFields()
    .filter((field) => field instanceof PDFSignature)
    .map((field) => ({
      field: field.getName(),
      dict: field.acroField.dict.lookupMaybe(PDFName.of("V"), PDFDict),
    }))
    .filter((entry) => entry.dict);
}
function signatureBytes(dict) {
  const value = dict.lookup(PDFName.of("Contents"));
  if (!(value instanceof PDFHexString || value instanceof PDFString))
    fail("/Contents string алга.");
  return buffer(value.asBytes());
}
function byteRange(dict, size) {
  const array = dict.lookupMaybe(PDFName.of("ByteRange"), PDFArray);
  if (!array || array.size() !== 4)
    fail("/ByteRange нь дөрвөн бүхэл тоотой байх ёстой.");
  const values = Array.from({ length: 4 }, (_, i) =>
    array.lookup(i, PDFNumber).asNumber(),
  );
  const [start, first, second, length] = values;
  if (
    !values.every((n) => Number.isSafeInteger(n) && n >= 0) ||
    start !== 0 ||
    first === 0 ||
    second <= first ||
    length === 0 ||
    second > size ||
    length > size - second
  ) {
    fail("/ByteRange хязгаар буруу.");
  }
  return values;
}
function parseCms(contents) {
  const decoded = asn1js.fromBER(contents);
  if (decoded.offset === -1) fail("CMS ASN.1 задлах боломжгүй.");
  if (contents.subarray(decoded.offset).some((byte) => byte !== 0))
    fail("CMS-ийн дараа тэг биш нэмэлт байт байна.");
  const info = new pkijs.ContentInfo({ schema: decoded.result });
  if (info.contentType !== OID.signedData) fail("CMS SignedData биш.");
  return new pkijs.SignedData({ schema: info.content });
}
function attribute(info, oid) {
  const matches =
    info.signedAttrs?.attributes.filter((attr) => attr.type === oid) ?? [];
  if (matches.length !== 1 || matches[0].values.length !== 1)
    fail(`Signed attribute ${oid} байхгүй эсвэл давхардсан.`);
  return matches[0].values[0];
}
function certificateInfo(cert) {
  const x509 = new X509Certificate(buffer(cert.toSchema().toBER(false)));
  const now = Date.now();
  return {
    subject: x509.subject,
    issuer: x509.issuer,
    serialNumber: x509.serialNumber,
    fingerprint256: x509.fingerprint256,
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    validNow:
      now >= Date.parse(x509.validFrom) && now <= Date.parse(x509.validTo),
  };
}
// ESS-ийн эхний certID нь яг зурагчийн гэрчилгээг bind хийх ёстой.
function checkEss(info, cert) {
  const attrs = info.signedAttrs?.attributes ?? [];
  const v2 = attrs.some((attr) => attr.type === OID.essV2);
  const v1 = attrs.some((attr) => attr.type === OID.ess);
  if (!v1 && !v2) return false;
  for (const oid of [v1 && OID.ess, v2 && OID.essV2].filter(Boolean)) {
    const value = attribute(info, oid);
    const certId = value.valueBlock.value?.[0]?.valueBlock.value?.[0];
    const parts = certId?.valueBlock.value;
    if (!Array.isArray(parts))
      fail("SigningCertificate attribute бүтэц буруу.");
    let index = 0;
    let algorithm = oid === OID.ess ? "sha1" : "sha256";
    if (parts[0] instanceof asn1js.Sequence) {
      if (oid === OID.ess) fail("SigningCertificate v1 hash algorithm буруу.");
      algorithm =
        HASHES[
          new pkijs.AlgorithmIdentifier({ schema: parts[index++] }).algorithmId
        ];
    }
    if (!algorithm) fail("SigningCertificate hash algorithm дэмжигдээгүй.");
    const certHash = parts[index];
    if (
      !(certHash instanceof asn1js.OctetString) ||
      !hash(algorithm, buffer(cert.toSchema().toBER(false))).equals(
        buffer(certHash.valueBlock.valueHexView),
      )
    ) {
      fail("SigningCertificate hash зурагчийн гэрчилгээтэй таарахгүй.");
    }
  }
  return true;
}

export async function loadAnchors(path) {
  if (!path) return [];
  const files = (await stat(path)).isDirectory()
    ? (await readdir(path))
        .filter((file) => /\.(pem|cer|crt|der)$/i.test(file))
        .sort()
        .map((file) => join(path, file))
    : [path];
  const certs = [];
  for (const file of files) {
    const bytes = await readFile(file);
    const pem = bytes
      .toString("ascii")
      .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    for (const input of pem ?? [bytes]) {
      const cert = new X509Certificate(input);
      certs.push(pkijs.Certificate.fromBER(cert.raw));
    }
  }
  if (!certs.length) fail("Trust Anchor гэрчилгээ олдсонгүй.");
  return certs;
}

export async function verifyPdf(
  pdf,
  {
    anchors = [],
    intermediates = [],
    online = false,
    allowPrivateNetwork = false,
    revocationOptions = {},
  } = {},
) {
  if (!buffer(pdf).subarray(0, 1024).includes(Buffer.from("%PDF-")))
    fail("PDF header олдсонгүй.");
  const document = await PDFDocument.load(pdf, {
    updateMetadata: false,
    throwOnInvalidObject: true,
  });
  const signatures = [];
  for (const entry of fields(document)) {
    const result = {
      field: entry.field,
      subFilter: name(entry.dict, "SubFilter"),
      claimedSigningTime: string(entry.dict, "M"),
      reason: string(entry.dict, "Reason"),
      cryptographicIntegrity: null,
      padesBasicChecks: null,
      signers: [],
      errors: [],
    };
    signatures.push(result);
    try {
      if (
        !["ETSI.CAdES.detached", "adbe.pkcs7.detached"].includes(
          result.subFilter,
        )
      ) {
        result.unsupported = true;
        fail(
          `SubFilter ${result.subFilter} дэмжигдээгүй (document timestamp/legacy формат байж болно).`,
        );
      }
      const range = byteRange(entry.dict, pdf.length);
      const [, first, second, length] = range;
      result.byteRange = range;
      result.signedRevisionBytes = second + length;
      result.coversCurrentFile = second + length === pdf.length;
      result.bytesAfterSignature = pdf.length - second - length;
      const contents = signatureBytes(entry.dict);

      const gap = pdf.subarray(first, second).toString("latin1");
      let gapBytes;
      if (/^<[\da-fA-F\s]*>$/.test(gap))
        gapBytes = buffer(PDFHexString.of(gap.slice(1, -1)).asBytes());
      else if (gap.startsWith("(") && gap.endsWith(")"))
        gapBytes = buffer(PDFString.of(gap.slice(1, -1)).asBytes());
      if (
        !gapBytes?.equals(contents) ||
        !/\/Contents\s*$/.test(
          pdf.subarray(Math.max(0, first - 128), first).toString("latin1"),
        )
      ) {
        fail("ByteRange-ийн нүх нь /Contents утгатай яг таарахгүй.");
      }
      if (
        !/%%EOF[\x00\t\n\f\r ]*$/.test(
          pdf
            .subarray(Math.max(0, second + length - 128), second + length)
            .toString("latin1"),
        )
      ) {
        fail("Гарын үсэг PDF revision-ийн төгсгөл хүртэл хамраагүй.");
      }
      const revision = await PDFDocument.load(
        pdf.subarray(0, second + length),
        { updateMetadata: false, throwOnInvalidObject: true },
      );
      const original = fields(revision).find(
        (field) => field.field === entry.field,
      );
      if (
        !original ||
        !signatureBytes(original.dict).equals(contents) ||
        byteRange(original.dict, second + length).some((n, i) => n !== range[i])
      ) {
        fail("Одоогийн signature field нь зурсан revision-ийнхтэй таарахгүй.");
      }
      const cms = parseCms(contents);
      if (
        cms.encapContentInfo.eContentType !== OID.data ||
        cms.encapContentInfo.eContent
      )
        fail("Detached CMS data байх ёстой.");
      if (!cms.signerInfos.length) fail("CMS SignerInfo алга.");
      const signedBytes = Buffer.concat([
        pdf.subarray(0, first),
        pdf.subarray(second, second + length),
      ]);
      for (let index = 0; index < cms.signerInfos.length; index++) {
        const info = cms.signerInfos[index];
        const signer = {
          digestAlgorithm:
            HASHES[info.digestAlgorithm.algorithmId] ??
            info.digestAlgorithm.algorithmId,
          signatureAlgorithm: info.signatureAlgorithm.algorithmId,
          integrity: false,
          chainTrusted: null,
          revocation: "not-checked",
          timestampPresent:
            info.unsignedAttrs?.attributes.some(
              (a) => a.type === OID.timestamp,
            ) ?? false,
        };
        result.signers.push(signer);
        const digestAlgorithm = HASHES[info.digestAlgorithm.algorithmId];
        if (!digestAlgorithm) {
          result.unsupported = true;
          fail("Digest algorithm дэмжигдээгүй.");
        }
        const contentType = attribute(info, OID.contentType);
        if (
          !(contentType instanceof asn1js.ObjectIdentifier) ||
          contentType.valueBlock.toString() !== OID.data
        )
          fail("CMS content-type буруу.");
        const digest = attribute(info, OID.digest);
        signer.digestMatches =
          digest instanceof asn1js.OctetString &&
          hash(digestAlgorithm, signedBytes).equals(
            buffer(digest.valueBlock.valueHexView),
          );
        if (!signer.digestMatches)
          fail(
            "PDF-ийн байт signed messageDigest-тэй таарахгүй: баримт өөрчлөгдсөн.",
          );
        const verified = await cms.verify({
          signer: index,
          data: signedBytes,
          checkChain: false,
          extendedMode: true,
        });
        signer.signatureValid = verified.signatureVerified === true;
        if (!signer.signatureValid || !verified.signerCertificate)
          fail("CMS гарын үсэг хүчинтэй биш.");
        signer.certificate = certificateInfo(verified.signerCertificate);
        signer.signingCertificateBound = checkEss(
          info,
          verified.signerCertificate,
        );
        signer.integrity = true;
        if (online) {
          const candidates = [
            ...(cms.certificates ?? []).filter(
              (cert) => cert instanceof pkijs.Certificate,
            ),
            ...intermediates,
            ...anchors,
          ];
          signer.revocation = await checkRevocation(
            verified.signerCertificate,
            candidates,
            { ...revocationOptions, allowPrivateNetwork },
          );
          // AIA-аас авсан issuer нь зөвхөн intermediate; Trust Anchor БИШ.
          cms.certificates = [
            ...(cms.certificates ?? []),
            ...candidates.filter(
              (cert) =>
                !(cms.certificates ?? []).some(
                  (existing) =>
                    existing instanceof pkijs.Certificate &&
                    buffer(existing.toSchema().toBER(false)).equals(
                      buffer(cert.toSchema().toBER(false)),
                    ),
                ),
            ),
          ];
        } else if (intermediates.length) {
          cms.certificates = [...(cms.certificates ?? []), ...intermediates];
        }
        if (anchors.length) {
          try {
            signer.chainTrusted = await cms.verify({
              signer: index,
              data: signedBytes,
              checkChain: true,
              trustedCerts: anchors,
              checkDate: new Date(),
              passedWhenNotRevValues: true,
            });
          } catch (error) {
            signer.chainTrusted = false;
            signer.chainError = error.message;
          }
        }
      }
      result.cryptographicIntegrity = result.signers.every(
        (signer) => signer.integrity,
      );
      result.padesBasicChecks =
        result.subFilter === "ETSI.CAdES.detached" &&
        cms.signerInfos.length === 1 &&
        result.signers.every(
          (signer) =>
            signer.signingCertificateBound && signer.digestAlgorithm !== "sha1",
        );
    } catch (error) {
      result.errors.push(error.message);
      result.cryptographicIntegrity = result.unsupported ? null : false;
    }
  }
  const integrity =
    signatures.length > 0 &&
    signatures.every((signature) => signature.cryptographicIntegrity === true);
  const coverage = signatures.some(
    (signature) =>
      signature.cryptographicIntegrity === true && signature.coversCurrentFile,
  );
  const revocations = signatures.flatMap((signature) =>
    signature.signers.map((signer) => signer.revocation),
  );
  // Нэг ч гарын үсэг timestamp-гүй бол зурсан цаг ТУСГААР шалтгаанаар нотлогдохгүй;
  // тайлан түүнийг ИЛД хэлэх ёстой — ерөнхий «token шалгаагүй» гэсэн үг биш.
  // Гарын үсэг зурсны ДАРАА байт нэмэгдсэн гарын үсэгийн тоо. Эдгээр нэмэлтүүд
  // өөрсдөө зурагдсан байж болох боловч ЭРТНИЙ зурагчийн ХАРСАН хуудасыг
  // өөрчлөх боломжтой — тэр ялгааг энэ хэрэгсэл шалгадаггүй.
  const supersededSignatures = signatures.filter(
    (signature) => (signature.bytesAfterSignature ?? 0) > 0,
  ).length;
  const timestamped = signatures.some((signature) =>
    signature.signers.some((signer) => signer.timestampPresent),
  );
  const revocationStatus = !online
    ? "not-checked"
    : revocations.some((value) => value?.status === "revoked")
      ? "revoked"
      : revocations.length > 0 &&
          revocations.every((value) => value?.status === "good")
        ? "good"
        : "unknown";
  return {
    format: "pdf-signature-report/2",
    checkedAt: new Date().toISOString(),
    bytes: pdf.length,
    sha256: hash("sha256", pdf).toString("hex"),
    signatureCount: signatures.length,
    // 🔴 `integrity-valid` = КРИПТОГРАФ зөв БОЛОН гэрчилгээ цуцлагдаагүй гэдэг ТОГТООГДСОН.
    //
    //    2026-09-17 хүртэл `revocationStatus !== "unknown"` гэж байсан — тиймээс
    //    офлайн ажиллуулалт (`"not-checked"`) exit 0 өгч, асуугаад хариу аваагүй
    //    ажиллуулалт (`"unknown"`) exit 2 өгдөг байв. Гэтэл хоёуланд нь
    //    цуцлалтын төлөв ЯГ АДИЛХАН мэдэгдэхгүй — ялгаа нь зөвхөн «асуусан уу» гэдэгт.
    //
    //    Үр дагавар нь буруу тал руу хазайсан: ИЛҮҮ ИХИЙГ шалгасан ажиллуулалт
    //    МУУ хариу өгч, юу ч шалгаагүй нь ногоон байв. Хэрэглэгч түүнийг сурвал
    //    `--online`-ыг ашиглахаа болино. ADR-гүй шийдвэр: алдаа нь ямагт АЮУЛГҮЙ тал руу
    //    унах ёстой (`mode.ts`-ийн зарчмыг дагав). ETSI EN 319 102-1 мөн цуцлалтын
    //    мэдээлэлгүй бол INDETERMINATE гэдгийг шаарддаг.
    //
    //    ⚠ Одоо офлайн ажиллуулалт ХЭЗЭЭ Ч exit 0 өгөхгүй. Энэ нь зориуд.
    status:
      !signatures.length ||
      signatures.some(
        (signature) => signature.cryptographicIntegrity === false,
      ) ||
      revocationStatus === "revoked"
        ? "invalid"
        : integrity && coverage && revocationStatus === "good"
          ? "integrity-valid"
          : "indeterminate",
    cryptographicIntegrity: integrity,
    currentFileCovered: coverage,
    padesValidity: "indeterminate",
    trustAnchorsProvided: anchors.length,
    signatures,
    revocationStatus,
    limitations: [
      // Цуцлалтын мөр нь тугаас биш, ҮР ДҮНГЭЭС гарна: `--online` өгсөн боловч
      // OCSP/CRL хүрээгүй бол «шалгасан» гэж хэлэх нь худал болно.
      revocationStatus === "revoked"
        ? "Зурагчийн гэрчилгээ цуцлагдсан байна."
        : revocationStatus === "good"
          ? "Цуцлалт шалгасан: гэрчилгээ хүчинтэй."
          : revocationStatus === "unknown"
            ? "Цуцлалт тогтоогдсонгүй: CA-гийн хаягаас хүлээсэн хариу ирсэнгүй. Шалтгааныг дээд хэсгээс харна уу."
            : "Цуцлалт шалгаагүй. --online нэмвэл CA-гаас асууна; дотоод хаягтай тестийн гэрчилгээнд --allow-private-network бас хэрэгтэй.",
      timestamped
        ? "Timestamp бий, гэхдээ TSA-гийн гарын үсгийг шалгаагүй тул зурсан цаг нотлогдоогүй."
        : "Timestamp байхгүй. Дээрх зурсан цагийг зурагч өөрөө бичсэн учраас нотлох баримт болохгүй.",
      supersededSignatures > 0
        ? `Эхний ${supersededSignatures} гарын үсгийн дараа файл дахин засагдсан. Тэдгээр зурагчийн харсан хувилбар одоогийнхоос өөр байж болно. DocMDP болон PAdES профайлыг энэ хэрэгсэл шалгадаггүй.`
        : "Гарын үсгийн дараа файлд юу ч нэмэгдээгүй. DocMDP болон PAdES профайлыг энэ хэрэгсэл шалгадаггүй.",
    ],
  };
}

function printReport(report) {
  const yes = (value) =>
    value === null || value === undefined
      ? "ШАЛГААГҮЙ"
      : value
        ? "ЗӨВ"
        : "БУРУУ";
  console.log(
    `\nPDF: ${report.file}\nSHA-256: ${report.sha256}\nГарын үсэг: ${report.signatureCount}`,
  );
  console.log(
    `Криптограф: ${yes(report.cryptographicIntegrity)} · Одоогийн файлыг бүтэн хамарсан: ${yes(report.currentFileCovered)}`,
  );
  for (const [index, signature] of report.signatures.entries()) {
    console.log(`\n[${index + 1}] ${signature.field} · ${signature.subFilter}`);
    console.log(
      `  Бүрэн бүтэн: ${yes(signature.cryptographicIntegrity)} · PAdES суурь шалгалт: ${yes(signature.padesBasicChecks)}`,
    );
    console.log(
      `  Зурснаас хойших байт: ${signature.bytesAfterSignature ?? "?"} · Зурагчийн зарласан цаг: ${signature.claimedSigningTime ?? "байхгүй"}`,
    );
    for (const signer of signature.signers) {
      console.log(
        `  Digest: ${signer.digestAlgorithm} · Signature OID: ${signer.signatureAlgorithm}`,
      );
      if (signer.certificate) {
        console.log(
          `  ${signer.certificate.subject}\n  Олгогч: ${signer.certificate.issuer}`,
        );
        console.log(
          `  Serial: ${signer.certificate.serialNumber}\n  Fingerprint: ${signer.certificate.fingerprint256}`,
        );
        console.log(
          `  Хугацаа: ${signer.certificate.validFrom} → ${signer.certificate.validTo} · Одоо: ${yes(signer.certificate.validNow)}`,
        );
      }
      console.log(
        `  CA гинж (одоогийн цагаар): ${yes(signer.chainTrusted)} · Timestamp байгаа: ${signer.timestampPresent ? "тийм (итгэлийг шалгаагүй)" : "үгүй"}`,
      );
      if (signer.revocation && typeof signer.revocation === "object") {
        const revocation = signer.revocation;
        console.log(
          `  Цуцлалт (одоо): ${revocation.status} · ${revocation.source ?? "OCSP/CRL"} · ${revocation.url ?? revocation.reason ?? ""}`,
        );
        if (revocation.thisUpdate)
          console.log(
            `  Хариуны хугацаа: ${revocation.thisUpdate} → ${revocation.nextUpdate ?? "nextUpdate байхгүй"}`,
          );
        for (const attempt of revocation.attempts)
          console.log(
            `    ${attempt.source}: ${attempt.url} → ${attempt.status}${attempt.reason ? " (" + attempt.reason + ")" : ""}`,
          );
      }
      if (signer.chainError) console.log(`  CA алдаа: ${signer.chainError}`);
    }
    for (const error of signature.errors) console.log(`  Алдаа: ${error}`);
  }
  console.log(
    `\nҮр дүн: ${report.status}\nPAdES бүрэн хүчинтэй эсэх: ТОГТООГДООГҮЙ`,
  );
  for (const limitation of report.limitations) console.log(`  • ${limitation}`);
}

/**
 * PDF path-ыг терминалаас асууна — аргументгүй ажиллуулсан үед.
 *
 * न `stdin.isTTY`-д ТУЛГУУРЛАХГҮЙ. Windows дээр Git Bash (MSYS2) нь Node-д
 *   жинхэнэ TTY өгдөггүй — `isTTY` нь `undefined` болно. Өмнө нь түүнд тулгуурласан
 *   тул интерактив терминал дээр хүртэл `node tools/verify-pades.mjs` нь prompt
 *   асуухын оронд шууд алдаа өгч байв (2026-09-17).
 *
 * Оронд нь мөр уншихыг ОРОЛДОНО. stdin нь хоосон (`< /dev/null`, pipe хаагдсан)
 * бол `close` нь хариунаас ӨМНӨ ирнэ — тэгвэл ЧАНГААР унана. Эс тэгвэл `question()`
 * хэзээ ч шийдэгдэхгүй тул процесс ГАРАЛТГҮЙ, exit 0-той чимээгүй гарна.
 */
async function askForPath() {
  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await Promise.race([
      prompt.question("PDF файлын path: "),
      new Promise((_resolve, reject) => {
        prompt.once("close", () =>
          reject(
            new Error(
              "PDF path өгнө үү — аргументээр эсвэл терминалаас. --help-ийг үзнэ үү.",
            ),
          ),
        );
      }),
    ]);
    // Windows-ын "Copy as path" нь хашилттай хуулдаг.
    return answer.trim().replace(/^"(.*)"$/, "$1");
  } finally {
    prompt.close();
  }
}

export async function main(args = process.argv.slice(2)) {
  let file;
  let anchorsPath;
  let intermediatesPath;
  let online = false;
  let allowPrivateNetwork = false;
  let json = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") {
      console.log(
        "Хэрэглээ: verify-pades.exe [PDF path] [--anchors CA.pem|хавтас] [--intermediates issuer.pem|хавтас] [--online] [--allow-private-network] [--json]\nPath өгөөгүй бол prompt асууна. Exit: 0 integrity-valid, 1 invalid, 2 indeterminate/алдаа.\nExit 0 гарахад цуцлалт тогтоогдсон байх шаардлагатай — тиймээс --online хэрэгтэй.\nExit 0 нь PAdES бүрэн баталгаажсан гэсэн үг биш.",
      );
      return 0;
    }
    if (arg === "--json") json = true;
    else if (arg === "--online") online = true;
    else if (arg === "--allow-private-network") allowPrivateNetwork = true;
    else if (arg === "--intermediates") {
      intermediatesPath = args[++index];
      if (!intermediatesPath || intermediatesPath.startsWith("--"))
        fail("--intermediates утга дутуу.");
    } else if (arg === "--anchors") {
      anchorsPath = args[++index];
      if (!anchorsPath || anchorsPath.startsWith("--"))
        fail("--anchors утга дутуу.");
    } else if (arg.startsWith("-")) fail(`Үл мэдэгдэх option: ${arg}`);
    else if (file) fail("Нэг PDF path өгнө үү.");
    else file = arg;
  }
  if (allowPrivateNetwork && !online)
    fail("--allow-private-network нь --online-той хамт хэрэглэгдэнэ.");
  if (!file) {
    if (json)
      fail("--json үед PDF path-ыг аргументаар өгнө үү — prompt асуухгүй.");
    file = await askForPath();
    if (!file) fail("PDF path хоосон байна.");
  }
  const path = resolve(file);
  const info = await stat(path).catch((error) =>
    fail(
      error.code === "ENOENT"
        ? `Файл олдсонгүй: ${path}`
        : `Файлыг нээж чадсангүй: ${path} (${error.code ?? error.message})`,
    ),
  );
  if (info.isDirectory()) fail(`Энэ нь хавтас, PDF файл биш: ${path}`);
  if (info.size > 256 * 1024 * 1024) fail("PDF 256 MB-аас том байна.");
  const report = {
    file: path,
    ...(await verifyPdf(await readFile(path), {
      anchors: await loadAnchors(anchorsPath),
      intermediates: await loadAnchors(intermediatesPath),
      online,
      allowPrivateNetwork,
    })),
  };
  if (json) console.log(JSON.stringify(report, null, 2));
  else printReport(report);
  return report.status === "invalid"
    ? 1
    : report.status === "integrity-valid"
      ? 0
      : 2;
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      if (process.argv.includes("--json"))
        console.log(JSON.stringify({ status: "error", error: error.message }));
      else console.error(`Алдаа: ${error.message}`);
      process.exitCode = 2;
    });
}
