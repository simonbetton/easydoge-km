import EasyDogeKM from "@easydoge/km-expo";
import { Text } from "react-native";

// scripts/verify-expo-native.sh installs @easydoge/km-expo from the packed
// tarball before bundling; it is deliberately absent from package.json.
export default function App() {
  return <Text>{typeof EasyDogeKM.generateMnemonic}</Text>;
}
