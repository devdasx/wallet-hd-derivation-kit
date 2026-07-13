/// Offline, native multi-chain HD-wallet key and address derivation.
library;

import 'package:blockchain_utils/blockchain_utils.dart';

const int apiSchemaVersion = 1;
const int hardenedOffset = 0x80000000;

class WalletHDDerivationException implements Exception {
  const WalletHDDerivationException(this.message);
  final String message;

  @override
  String toString() => 'WalletHDDerivationException: $message';
}

class _Format {
  const _Format(
      this.name, this.public, this.private, this.purpose, this.script);
  final String name;
  final String public;
  final String private;
  final int purpose;
  final String script;
}

const _formats = <String, _Format>{
  'xpub': _Format('xpub', '0488b21e', '0488ade4', 44, 'p2pkh'),
  'ypub': _Format('ypub', '049d7cb2', '049d7878', 49, 'p2sh-p2wpkh'),
  'zpub': _Format('zpub', '04b24746', '04b2430c', 84, 'p2wpkh'),
  'tpub': _Format('tpub', '043587cf', '04358394', 44, 'p2pkh'),
  'upub': _Format('upub', '044a5262', '044a4e28', 49, 'p2sh-p2wpkh'),
  'vpub': _Format('vpub', '045f1cf6', '045f18bc', 84, 'p2wpkh'),
  'Ltub': _Format('Ltub', '019da462', '019d9cfe', 44, 'p2pkh'),
  'Mtub': _Format('Mtub', '01b26ef6', '01b26792', 49, 'p2sh-p2wpkh'),
};

class ChainInfo {
  const ChainInfo({
    required this.id,
    required this.name,
    required this.symbol,
    required this.coinType,
    required this.curve,
    required this.defaultScriptType,
    this.defaultFormat,
    this.p2pkh = const [],
    this.p2sh = const [],
    this.hrp,
  });

  final String id;
  final String name;
  final String symbol;
  final int coinType;
  final String curve;
  final String defaultScriptType;
  final String? defaultFormat;
  final List<int> p2pkh;
  final List<int> p2sh;
  final String? hrp;

  Map<String, Object?> toJson() => {
        'id': id,
        'name': name,
        'symbol': symbol,
        'coinType': coinType,
        'curve': curve,
        'defaultFormat': defaultFormat,
        'defaultScriptType': defaultScriptType,
        'p2pkh': BytesUtils.toHexString(p2pkh),
        'p2sh': BytesUtils.toHexString(p2sh),
        'hrp': hrp,
      };
}

const _chains = <ChainInfo>[
  ChainInfo(
      id: 'bitcoin',
      name: 'Bitcoin',
      symbol: 'BTC',
      coinType: 0,
      curve: 'secp256k1',
      defaultFormat: 'zpub',
      defaultScriptType: 'p2wpkh',
      p2pkh: [0],
      p2sh: [5],
      hrp: 'bc'),
  ChainInfo(
      id: 'bitcoin-testnet',
      name: 'Bitcoin Testnet',
      symbol: 'TBTC',
      coinType: 1,
      curve: 'secp256k1',
      defaultFormat: 'vpub',
      defaultScriptType: 'p2wpkh',
      p2pkh: [0x6f],
      p2sh: [0xc4],
      hrp: 'tb'),
  ChainInfo(
      id: 'litecoin',
      name: 'Litecoin',
      symbol: 'LTC',
      coinType: 2,
      curve: 'secp256k1',
      defaultFormat: 'Ltub',
      defaultScriptType: 'p2pkh',
      p2pkh: [0x30],
      p2sh: [0x32],
      hrp: 'ltc'),
  ChainInfo(
      id: 'dogecoin',
      name: 'Dogecoin',
      symbol: 'DOGE',
      coinType: 3,
      curve: 'secp256k1',
      defaultFormat: 'xpub',
      defaultScriptType: 'p2pkh',
      p2pkh: [0x1e],
      p2sh: [0x16]),
  ChainInfo(
      id: 'dash',
      name: 'Dash',
      symbol: 'DASH',
      coinType: 5,
      curve: 'secp256k1',
      defaultFormat: 'xpub',
      defaultScriptType: 'p2pkh',
      p2pkh: [0x4c],
      p2sh: [0x10]),
  ChainInfo(
      id: 'digibyte',
      name: 'DigiByte',
      symbol: 'DGB',
      coinType: 20,
      curve: 'secp256k1',
      defaultFormat: 'xpub',
      defaultScriptType: 'p2pkh',
      p2pkh: [0x1e],
      p2sh: [0x3f],
      hrp: 'dgb'),
  ChainInfo(
      id: 'bitcoin-cash',
      name: 'Bitcoin Cash',
      symbol: 'BCH',
      coinType: 145,
      curve: 'secp256k1',
      defaultFormat: 'xpub',
      defaultScriptType: 'cashaddr',
      p2pkh: [0],
      p2sh: [5]),
  ChainInfo(
      id: 'zcash-transparent',
      name: 'Zcash Transparent',
      symbol: 'ZEC',
      coinType: 133,
      curve: 'secp256k1',
      defaultFormat: 'xpub',
      defaultScriptType: 'p2pkh',
      p2pkh: [0x1c, 0xb8],
      p2sh: [0x1c, 0xbd]),
  ChainInfo(
      id: 'ethereum',
      name: 'Ethereum',
      symbol: 'ETH',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'ethereum-classic',
      name: 'Ethereum Classic',
      symbol: 'ETC',
      coinType: 61,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'polygon',
      name: 'Polygon',
      symbol: 'POL',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'bsc',
      name: 'BNB Smart Chain',
      symbol: 'BNB',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'avalanche-c',
      name: 'Avalanche C-Chain',
      symbol: 'AVAX',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'arbitrum',
      name: 'Arbitrum',
      symbol: 'ARB',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'optimism',
      name: 'Optimism',
      symbol: 'OP',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'base',
      name: 'Base',
      symbol: 'ETH',
      coinType: 60,
      curve: 'secp256k1',
      defaultScriptType: 'evm'),
  ChainInfo(
      id: 'tron',
      name: 'TRON',
      symbol: 'TRX',
      coinType: 195,
      curve: 'secp256k1',
      defaultScriptType: 'tron'),
  ChainInfo(
      id: 'solana',
      name: 'Solana',
      symbol: 'SOL',
      coinType: 501,
      curve: 'ed25519',
      defaultScriptType: 'solana'),
];

List<ChainInfo> supportedChains() => List.unmodifiable(_chains);

ChainInfo _chain(String id) {
  for (final chain in _chains) {
    if (chain.id == id) return chain;
  }
  throw WalletHDDerivationException('unsupported chain: $id');
}

List<int> _sourceSeed(Map<String, Object?> source) {
  List<int> seed;
  if (source['seed'] case final List<int> value) {
    seed = List.of(value);
  } else if (source['seedHex'] case final String value) {
    seed = BytesUtils.fromHexString(value);
  } else if (source['mnemonic'] case final String value) {
    final phrase = value.trim().split(RegExp(r'\s+')).join(' ');
    try {
      if (source['validate'] != false &&
          !Bip39MnemonicValidator(Bip39Languages.english)
              .validateWords(phrase)) {
        throw const WalletHDDerivationException(
            'invalid BIP39 English mnemonic');
      }
      seed = Bip39SeedGenerator(Mnemonic.fromString(phrase))
          .generate((source['passphrase'] as String?) ?? '');
    } on WalletHDDerivationException {
      rethrow;
    } catch (_) {
      throw const WalletHDDerivationException('invalid BIP39 English mnemonic');
    }
  } else {
    throw const WalletHDDerivationException(
        'source must provide mnemonic, seed, or seedHex');
  }
  if (seed.length < 16 || seed.length > 64) {
    throw const WalletHDDerivationException(
        'seed must be between 16 and 64 bytes');
  }
  return seed;
}

String _path(String path, {bool ed25519 = false}) {
  if (path == 'm') return path;
  if (!path.startsWith('m/')) {
    throw const WalletHDDerivationException(
        'path must be absolute and start with m');
  }
  final parts = path.substring(2).split('/');
  if (parts.isEmpty || parts.length > 255) {
    throw const WalletHDDerivationException(
        'path depth must be between 1 and 255');
  }
  final normalized = <String>[];
  for (var part in parts) {
    final hardened =
        part.endsWith("'") || part.endsWith('h') || part.endsWith('H');
    if (hardened) part = part.substring(0, part.length - 1);
    if (!RegExp(r'^(0|[1-9][0-9]*)$').hasMatch(part)) {
      throw WalletHDDerivationException('invalid path component: $part');
    }
    final index = int.parse(part);
    if (index >= hardenedOffset) {
      throw const WalletHDDerivationException('path index is too large');
    }
    if (ed25519 && !hardened) {
      throw const WalletHDDerivationException(
          'SLIP-0010 Ed25519 supports hardened children only');
    }
    normalized.add("$index${hardened ? "'" : ''}");
  }
  return 'm/${normalized.join('/')}';
}

_Format _format(ChainInfo chain, String? requested, String? script) {
  final name =
      requested ?? (script == 'p2tr' ? 'xpub' : chain.defaultFormat ?? 'xpub');
  final format = _formats[name];
  if (format == null) {
    throw WalletHDDerivationException('unsupported extended-key format: $name');
  }
  final allowed = switch (chain.id) {
    'bitcoin' => const ['xpub', 'ypub', 'zpub'],
    'bitcoin-testnet' => const ['tpub', 'upub', 'vpub'],
    'litecoin' => const ['Ltub', 'Mtub'],
    _ => const ['xpub'],
  };
  if (!allowed.contains(name)) {
    throw WalletHDDerivationException(
        'format $name is not registered for ${chain.id}');
  }
  return format;
}

Bip32KeyNetVersions _versions(_Format format) => Bip32KeyNetVersions(
    BytesUtils.fromHexString(format.public),
    BytesUtils.fromHexString(format.private));

String _accountPath(
    ChainInfo chain, int account, String? script, _Format format) {
  _index(account, 'account');
  final purpose = script == 'p2tr' ? 86 : format.purpose;
  return "m/$purpose'/${chain.coinType}'/$account'";
}

int _index(int value, String name) {
  if (value < 0 || value >= hardenedOffset) {
    throw WalletHDDerivationException('$name must be between 0 and 2147483647');
  }
  return value;
}

Map<String, Object?> deriveNode(
    {required Map<String, Object?> source,
    String curve = 'secp256k1',
    String path = 'm'}) {
  final seed = _sourceSeed(source);
  if (curve == 'ed25519') {
    final node = Bip32Slip10Ed25519.fromSeed(seed)
        .derivePath(_path(path, ed25519: true));
    return {
      'schemaVersion': 1,
      'curve': curve,
      'path': path,
      'publicKeyHex':
          BytesUtils.toHexString(node.publicKey.compressed.sublist(1)),
      'chainCodeHex': BytesUtils.toHexString(node.chainCode.toBytes()),
      'depth': node.depth.toInt(),
      'childNumber': node.index.toInt()
    };
  }
  if (curve != 'secp256k1') {
    throw WalletHDDerivationException('unsupported curve: $curve');
  }
  final node = Bip32Slip10Secp256k1.fromSeed(seed).derivePath(_path(path));
  return {
    'schemaVersion': 1,
    'curve': curve,
    'path': path,
    'publicKeyHex': BytesUtils.toHexString(node.publicKey.compressed),
    'chainCodeHex': BytesUtils.toHexString(node.chainCode.toBytes()),
    'depth': node.depth.toInt(),
    'childNumber': node.index.toInt()
  };
}

Map<String, Object?> deriveAccountPublicKey(
    {required Map<String, Object?> source,
    String chain = 'bitcoin',
    String? scriptType,
    int account = 0,
    String? format,
    String? path}) {
  final info = _chain(chain);
  if (info.curve == 'ed25519') {
    throw const WalletHDDerivationException(
        'Solana SLIP-0010 does not define extended public keys');
  }
  final fmt = _format(info, format, scriptType);
  final resolvedPath =
      _path(path ?? _accountPath(info, account, scriptType, fmt));
  final node =
      Bip32Slip10Secp256k1.fromSeed(_sourceSeed(source), _versions(fmt))
          .derivePath(resolvedPath);
  return {
    'schemaVersion': 1,
    'chain': chain,
    'curve': info.curve,
    'path': resolvedPath,
    'format': fmt.name,
    'extendedPublicKey': node.publicKey.toExtended,
    'publicKeyHex': BytesUtils.toHexString(node.publicKey.compressed)
  };
}

Map<String, Object?> deriveAccountPrivateKey(
    {required Map<String, Object?> source,
    String chain = 'bitcoin',
    String? scriptType,
    int account = 0,
    String? format,
    String? path}) {
  final info = _chain(chain);
  if (info.curve == 'ed25519') {
    final resolvedPath =
        _path(path ?? "m/44'/${info.coinType}'/$account'", ed25519: true);
    final node = Bip32Slip10Ed25519.fromSeed(_sourceSeed(source))
        .derivePath(resolvedPath);
    return {
      'schemaVersion': 1,
      'chain': chain,
      'curve': info.curve,
      'path': resolvedPath,
      'format': null,
      'extendedPrivateKey': null,
      'privateKeyHex': BytesUtils.toHexString(node.privateKey.raw),
      'publicKeyHex':
          BytesUtils.toHexString(node.publicKey.compressed.sublist(1))
    };
  }
  final fmt = _format(info, format, scriptType);
  final resolvedPath =
      _path(path ?? _accountPath(info, account, scriptType, fmt));
  final node =
      Bip32Slip10Secp256k1.fromSeed(_sourceSeed(source), _versions(fmt))
          .derivePath(resolvedPath);
  return {
    'schemaVersion': 1,
    'chain': chain,
    'curve': info.curve,
    'path': resolvedPath,
    'format': fmt.name,
    'extendedPrivateKey': node.privateKey.toExtended,
    'privateKeyHex': BytesUtils.toHexString(node.privateKey.raw),
    'publicKeyHex': BytesUtils.toHexString(node.publicKey.compressed)
  };
}

Map<String, Object?> deriveAddress(
    {required Map<String, Object?> source,
    String chain = 'bitcoin',
    int account = 0,
    int change = 0,
    int index = 0,
    String? scriptType,
    String? format,
    String? path}) {
  final info = _chain(chain);
  _index(account, 'account');
  _index(change, 'change');
  _index(index, 'index');
  final script = scriptType ?? info.defaultScriptType;
  if (info.curve == 'ed25519') {
    final resolvedPath = _path(
        path ?? "m/44'/${info.coinType}'/$account'/$index'",
        ed25519: true);
    final node = Bip32Slip10Ed25519.fromSeed(_sourceSeed(source))
        .derivePath(resolvedPath);
    final public = node.publicKey.compressed;
    return _addressResult(info, resolvedPath, account, change, index, script,
        SolAddrEncoder().encodeKey(public), public.sublist(1));
  }
  final fmt = _format(info, format, script);
  final resolvedPath = _path(
      path ?? '${_accountPath(info, account, script, fmt)}/$change/$index');
  final node = Bip32Slip10Secp256k1.fromSeed(_sourceSeed(source))
      .derivePath(resolvedPath);
  final public = node.publicKey.compressed;
  return _addressResult(info, resolvedPath, account, change, index, script,
      _publicKeyAddress(public, info, script), public);
}

List<Map<String, Object?>> deriveAddresses(
    {required Map<String, Object?> source,
    String chain = 'bitcoin',
    int account = 0,
    int change = 0,
    int start = 0,
    int count = 20,
    String? scriptType,
    String? format}) {
  _index(start, 'start');
  if (count < 1 || count > 10000 || start + count > hardenedOffset) {
    throw const WalletHDDerivationException(
        'count must be between 1 and 10000 and stay within the index range');
  }
  return List.generate(
      count,
      (offset) => deriveAddress(
          source: source,
          chain: chain,
          account: account,
          change: change,
          index: start + offset,
          scriptType: scriptType,
          format: format));
}

Map<String, Object?> _addressResult(
        ChainInfo chain,
        String path,
        int account,
        int change,
        int index,
        String script,
        String address,
        List<int> public) =>
    {
      'schemaVersion': 1,
      'chain': chain.id,
      'curve': chain.curve,
      'path': path,
      'account': account,
      'change': change,
      'index': index,
      'scriptType': script,
      'address': address,
      'publicKeyHex': BytesUtils.toHexString(public)
    };

String _publicKeyAddress(List<int> public, ChainInfo chain, String script) {
  return switch (script) {
    'p2pkh' => P2PKHAddrEncoder().encodeKey(public, netVersion: chain.p2pkh),
    'p2sh-p2wpkh' =>
      P2SHAddrEncoder().encodeKey(public, netVersion: chain.p2sh),
    'p2wpkh' => P2WPKHAddrEncoder().encodeKey(public, hrp: chain.hrp),
    'p2tr' => P2TRAddrEncoder().encodeKey(public, hrp: chain.hrp),
    'cashaddr' => BchP2PKHAddrEncoder()
        .encodeKey(public, hrp: 'bitcoincash', netVersion: const [0]),
    'evm' => EthAddrEncoder().encodeKey(public),
    'tron' => TrxAddrEncoder().encodeKey(public),
    _ => throw WalletHDDerivationException('unsupported script type: $script'),
  };
}

class ParsedExtendedKey {
  ParsedExtendedKey._(
      {required this.value,
      required this.versionHex,
      required this.format,
      required this.isPrivate,
      required this.depth,
      required this.childNumber,
      required this.parentFingerprintHex,
      required this.chainCodeHex,
      required this.publicKeyHex,
      required Bip32Slip10Secp256k1 node})
      : _node = node;
  final String value;
  final String versionHex;
  final String format;
  final bool isPrivate;
  final int depth;
  final int childNumber;
  final String parentFingerprintHex;
  final String chainCodeHex;
  final String publicKeyHex;
  final Bip32Slip10Secp256k1 _node;

  Map<String, Object?> toJson() => {
        'value': value,
        'versionHex': versionHex,
        'format': format,
        'isPrivate': isPrivate,
        'depth': depth,
        'childNumber': childNumber,
        'parentFingerprintHex': parentFingerprintHex,
        'chainCodeHex': chainCodeHex,
        'publicKeyHex': publicKeyHex
      };
}

ParsedExtendedKey parseExtendedKey(String value) {
  try {
    final payload = Base58Decoder.checkDecode(value);
    if (payload.length != 78) {
      throw const WalletHDDerivationException(
          'extended key payload must be 78 bytes');
    }
    final versionHex = BytesUtils.toHexString(payload.sublist(0, 4));
    final isPrivate = payload[45] == 0;
    final entry = _formats.entries
        .where((entry) =>
            versionHex ==
            (isPrivate ? entry.value.private : entry.value.public))
        .firstOrNull;
    if (entry == null) {
      throw WalletHDDerivationException(
          'unknown extended-key version: $versionHex');
    }
    final depth = payload[4];
    if (depth == 0 &&
        (payload.sublist(5, 9).any((byte) => byte != 0) ||
            payload.sublist(9, 13).any((byte) => byte != 0))) {
      throw const WalletHDDerivationException(
          'root extended key must have zero parent fingerprint and child number');
    }
    final node =
        Bip32Slip10Secp256k1.fromExtendedKey(value, _versions(entry.value));
    return ParsedExtendedKey._(
        value: value,
        versionHex: versionHex,
        format: entry.key,
        isPrivate: isPrivate,
        depth: node.depth.toInt(),
        childNumber: node.index.toInt(),
        parentFingerprintHex:
            BytesUtils.toHexString(node.parentFingerPrint.toBytes()),
        chainCodeHex: BytesUtils.toHexString(node.chainCode.toBytes()),
        publicKeyHex: BytesUtils.toHexString(node.publicKey.compressed),
        node: node);
  } catch (error) {
    if (error is WalletHDDerivationException) rethrow;
    throw const WalletHDDerivationException(
        'invalid extended key checksum or material');
  }
}

String serializeExtendedKey(ParsedExtendedKey parsed,
    {bool private = false, String? format}) {
  final selected = _formats[format ?? parsed.format];
  if (selected == null) {
    throw WalletHDDerivationException(
        'unsupported extended-key format: $format');
  }
  if (private && parsed._node.isPublicOnly) {
    throw const WalletHDDerivationException(
        'private material is not available from an extended public key');
  }
  final sourceValue = private
      ? parsed._node.privateKey.toExtended
      : parsed._node.publicKey.toExtended;
  final payload = Base58Decoder.checkDecode(sourceValue);
  final version =
      BytesUtils.fromHexString(private ? selected.private : selected.public);
  return Base58Encoder.checkEncode([...version, ...payload.sublist(4)]);
}

Map<String, Object?> deriveAddressFromExtendedPublicKey(
    {required String extendedPublicKey,
    required String chain,
    int change = 0,
    int index = 0,
    String? scriptType}) {
  final info = _chain(chain);
  if (info.curve != 'secp256k1') {
    throw const WalletHDDerivationException(
        'extended public derivation is available only for secp256k1 chains');
  }
  final parsed = parseExtendedKey(extendedPublicKey);
  if (parsed.isPrivate) {
    throw const WalletHDDerivationException(
        'use an extended public key, not an extended private key');
  }
  _index(change, 'change');
  _index(index, 'index');
  final node = parsed._node
      .childKey(Bip32KeyIndex(change))
      .childKey(Bip32KeyIndex(index));
  final script = scriptType ??
      switch (parsed.format) {
        'ypub' || 'upub' || 'Mtub' => 'p2sh-p2wpkh',
        'zpub' || 'vpub' => 'p2wpkh',
        _ => info.defaultScriptType
      };
  final public = node.publicKey.compressed;
  return _addressResult(info, '$change/$index', 0, change, index, script,
      _publicKeyAddress(public, info, script), public);
}
