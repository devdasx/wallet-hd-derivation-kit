import React from "react";
import { Text, View } from "react-native";
import { deriveAddress } from "wallet-hd-derivation-kit/react-native";

const source = { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" };

export default function App() {
  const bitcoin = deriveAddress({ source, chain: "bitcoin" }).address;
  return <View><Text testID="bitcoin-address">{bitcoin}</Text></View>;
}
