import 'package:wallet_hd_derivation_kit/wallet_hd_derivation_kit.dart';

void main() {
  const source = {
    'mnemonic':
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  };
  print(deriveAddress(source: source, chain: 'bitcoin-cash')['address']);
}
