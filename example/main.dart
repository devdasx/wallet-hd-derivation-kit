import 'dart:io';

import 'package:wallet_hd_derivation_kit/wallet_hd_derivation_kit.dart';

void main() {
  final mnemonic = Platform.environment['WALLET_MNEMONIC'];
  if (mnemonic == null) {
    stderr.writeln('Set WALLET_MNEMONIC; never hard-code a real wallet secret.');
    exitCode = 2;
    return;
  }
  print(deriveAddress(source: {'mnemonic': mnemonic}, chain: 'bitcoin'));
}
