import 'package:flutter_test/flutter_test.dart';
import 'package:wallethd_flutter_example/main.dart';

void main() {
  testWidgets('renders the verified Solana vector', (tester) async {
    await tester.pumpWidget(const WalletHDExample());
    expect(find.text('HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk'), findsOneWidget);
  });
}
