import 'package:flutter/material.dart';
import 'package:wallet_hd_derivation_kit/wallet_hd_derivation_kit.dart';

void main() => runApp(const WalletHDExample());

class WalletHDExample extends StatelessWidget {
  const WalletHDExample({super.key});

  @override
  Widget build(BuildContext context) {
    const source = {
      'mnemonic':
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    };
    final address = deriveAddress(source: source, chain: 'solana')['address'];
    return MaterialApp(home: Scaffold(body: Center(child: SelectableText('$address'))));
  }
}
