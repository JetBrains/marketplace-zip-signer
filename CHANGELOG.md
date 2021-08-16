# Marketplace ZIP Signer Changelog

## 0.1.7
- CLI: Rename `key` and `cert` signing options accepting paths to files to `key-file` and `cert-file`
- CLI: Introduce `key` and `cert` signing options for string values

## 0.1.6
- Fix digest calculation in case of multiple digests
- Always update EOCD record before computing digests
- Add CLI to sign ZIP using Google KMS Signer
- Add `unsign` method to `ZipSigner`

## 0.1.5
- The initial release of the zip-signer library command-line interface
