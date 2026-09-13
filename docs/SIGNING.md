# Offline signing

Release keys never touch CI, the source tree or any network-connected
service. CI produces unsigned artifacts. The signing Mac turns them into
releases.

## One-time: key generation

1. Create an encrypted volume for the keys:

   ```
   hdiutil create -type SPARSEBUNDLE -fs APFS -encryption AES-256 \
       -size 1g -volname FortressKeys ~/FortressKeys.sparsebundle
   hdiutil attach ~/FortressKeys.sparsebundle
   ```

2. Generate the full set: 11 APK certificates, 75 APEX key pairs and the
   AVB key, 87 keys in all. RSA-4096, about a minute on Apple Silicon:

   ```
   signing/make_keys.sh /Volumes/FortressKeys/keys
   ```

   The script refuses to overwrite an existing key directory, and refuses
   any path inside this source tree or any other git work tree.

3. Back up `/Volumes/FortressKeys` to **two** offline media. Losing the keys
   means devices can no longer take OTA updates.
4. Publish `CERT-FINGERPRINTS.txt` (public certificates only) with the first
   release, so users can verify updates.

Keep the volume detached except while signing.

## Per release (Phase 2, partly still to be written)

Inputs, downloaded from the build (crave or own machine): the unsigned
`*-target_files*.zip` and `otatools.zip`, with their sha256 values from the
build log.

1. Check the artifact hashes against the build log.
2. `sign_target_files_apks` with `-d <keys>`, one `--extra_apks` per APEX
   and APEX-APK, and one `--extra_apex_payload_key` per APEX. This follows
   the LineageOS "Signing Builds" guide; `signing/sign_release.sh` will wrap
   it.
3. `ota_from_target_files -k <keys>/releasekey --block --backup=true`.
4. vbmeta signed with `avb.pem` (Phase 2 experiment, see
   [DEVICE_A52SXQ.md](DEVICE_A52SXQ.md)).
5. From Phase 12 on: refuse to sign unless a PASS report from the on-device
   security suite exists for the build fingerprint.

`otatools` contains x86_64 Linux binaries. On the M-series Mac they run in
an amd64 Linux container or VM under Rosetta. The container setup gets
fixed when the first target-files exist, because it cannot be tested
before then.
