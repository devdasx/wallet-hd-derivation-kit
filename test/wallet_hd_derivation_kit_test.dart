import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:wallet_hd_derivation_kit/wallet_hd_derivation_kit.dart';

const mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const source = <String, Object?>{'mnemonic': mnemonic};

void main() {
  test('SLIP-132 and watch-only derivation match', () {
    final account = deriveAccountPublicKey(source: source, format: 'zpub');
    const zpub =
        'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs';
    expect(account['extendedPublicKey'], zpub);
    final direct = deriveAddress(source: source);
    final watched = deriveAddressFromExtendedPublicKey(
        extendedPublicKey: zpub, chain: 'bitcoin');
    expect(direct['address'], 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    expect(watched['address'], direct['address']);
  });

  test('private export and serialization are explicit', () {
    final secret = deriveAccountPrivateKey(source: source, format: 'zpub');
    const zprv =
        'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE';
    expect(secret['extendedPrivateKey'], zprv);
    expect(serializeExtendedKey(parseExtendedKey(zprv), private: true), zprv);
  });

  test('all chain-family vectors match', () {
    const vectors = {
      'litecoin': 'LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez',
      'dogecoin': 'DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC',
      'dash': 'XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5',
      'digibyte': 'DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i',
      'bitcoin-cash': 'bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6',
      'zcash-transparent': 't1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F',
      'ethereum': '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
      'ethereum-classic': '0xFA22515E43658ce56A7682B801e9B5456f511420',
      'tron': 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH',
      'solana': 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk',
    };
    for (final entry in vectors.entries) {
      expect(deriveAddress(source: source, chain: entry.key)['address'],
          entry.value,
          reason: entry.key);
    }
  });

  test('BIP86 and validation boundaries match', () {
    expect(deriveAddress(source: source, scriptType: 'p2tr')['address'],
        'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
    expect(supportedChains(), hasLength(18));
    expect(() => deriveAddress(source: const {'mnemonic': 'abandon abandon'}),
        throwsA(isA<WalletHDDerivationException>()));
    expect(
        () => deriveNode(source: const {
              'seed': [1, 2, 3]
            }),
        throwsA(isA<WalletHDDerivationException>()));
    expect(
        deriveAddresses(source: source, chain: 'ethereum', start: 3, count: 4)
            .map((item) => item['index']),
        [3, 4, 5, 6]);
  });

  test('rejects every official BIP32 invalid extended key', () {
    final vectors =
        jsonDecode(File('test-vectors/bip32-official.json').readAsStringSync())
            as Map<String, Object?>;
    final invalid = vectors['invalidExtendedKeys']! as List<Object?>;
    for (final item in invalid.cast<Map<String, Object?>>()) {
      expect(() => parseExtendedKey(item['value']! as String),
          throwsA(isA<WalletHDDerivationException>()),
          reason: item['reason']! as String);
    }
  });

  test('covers public API branches and failure boundaries', () {
    expect(const WalletHDDerivationException('x').toString(),
        'WalletHDDerivationException: x');
    expect(supportedChains().first.toJson()['id'], 'bitcoin');
    expect(() => deriveAddress(source: source, chain: 'unknown'),
        throwsA(isA<WalletHDDerivationException>()));

    final seed = List<int>.generate(16, (index) => index);
    expect(deriveNode(source: {'seed': seed})['depth'], 0);
    expect(
        deriveNode(source: {
          'seedHex': seed.map((v) => v.toRadixString(16).padLeft(2, '0')).join()
        }),
        contains('publicKeyHex'));
    expect(
        deriveNode(source: source, curve: 'ed25519', path: "m/0h")['depth'], 1);
    expect(() => deriveNode(source: source, curve: 'p256'),
        throwsA(isA<WalletHDDerivationException>()));

    final solanaSecret =
        deriveAccountPrivateKey(source: source, chain: 'solana');
    expect(solanaSecret['extendedPrivateKey'], isNull);
    expect(solanaSecret['privateKeyHex'], isNotEmpty);
    expect(() => deriveAccountPublicKey(source: source, chain: 'solana'),
        throwsA(isA<WalletHDDerivationException>()));
    expect(() => deriveAccountPublicKey(source: source, format: 'unknown'),
        throwsA(isA<WalletHDDerivationException>()));
    expect(() => deriveAccountPublicKey(source: source, format: 'tpub'),
        throwsA(isA<WalletHDDerivationException>()));

    expect(
        deriveAddress(
                source: source,
                format: 'ypub',
                scriptType: 'p2sh-p2wpkh')['address']
            .toString(),
        startsWith('3'));
    expect(() => deriveAddress(source: source, scriptType: 'unknown'),
        throwsA(isA<WalletHDDerivationException>()));
    expect(() => deriveAddresses(source: source, count: 0),
        throwsA(isA<WalletHDDerivationException>()));
    expect(() => deriveAddress(source: source, index: -1),
        throwsA(isA<WalletHDDerivationException>()));

    final secret = deriveAccountPrivateKey(source: source, format: 'zpub');
    final parsedPrivate =
        parseExtendedKey(secret['extendedPrivateKey']! as String);
    expect(parsedPrivate.toJson()['isPrivate'], isTrue);
    expect(serializeExtendedKey(parsedPrivate, private: true),
        secret['extendedPrivateKey']);
    final public = deriveAccountPublicKey(source: source, format: 'ypub');
    final parsedPublic =
        parseExtendedKey(public['extendedPublicKey']! as String);
    expect(
        serializeExtendedKey(parsedPublic, format: 'xpub'), startsWith('xpub'));
    expect(() => serializeExtendedKey(parsedPublic, private: true),
        throwsA(isA<WalletHDDerivationException>()));
    expect(() => serializeExtendedKey(parsedPublic, format: 'unknown'),
        throwsA(isA<WalletHDDerivationException>()));
    expect(
        deriveAddressFromExtendedPublicKey(
                extendedPublicKey: public['extendedPublicKey']! as String,
                chain: 'bitcoin')['address']
            .toString(),
        startsWith('3'));
    expect(
        () => deriveAddressFromExtendedPublicKey(
            extendedPublicKey: secret['extendedPrivateKey']! as String,
            chain: 'bitcoin'),
        throwsA(isA<WalletHDDerivationException>()));

    for (final invalid in <Map<String, Object?>>[
      const {},
      const {
        'seed': [1, 2, 3]
      },
      const {'mnemonic': 'abandon abandon'},
    ]) {
      expect(() => deriveNode(source: invalid),
          throwsA(isA<WalletHDDerivationException>()));
    }
    for (final path in ['relative/0', 'm/00', 'm/abc', 'm/2147483648']) {
      expect(() => deriveNode(source: source, path: path),
          throwsA(isA<WalletHDDerivationException>()),
          reason: path);
    }
  });
}
