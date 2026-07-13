import 'dart:convert';

import 'package:wallet_hd_derivation_kit/wallet_hd_derivation_kit.dart';

void main() {
  const words =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final result = <String, String>{};
  for (final chain in supportedChains()) {
    result[chain.id] = deriveAddress(
      source: const {'mnemonic': words},
      chain: chain.id,
    )['address']! as String;
  }
  print('WALLETHD_CONFORMANCE=${jsonEncode(result)}');
}
