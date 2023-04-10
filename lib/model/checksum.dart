import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:pointycastle/digests/keccak.dart';

class CheckSum {
  /// This gist/function helps in convertion or verification of the ethereum address
  /// Why checksum is explained here: https://coincodex.com/article/2078/ethereum-address-checksum-explained/
  String toChecksum(String ethAddress) {
    // Checking for 0x prefix
    String addrWithoutChecksum =
        ethAddress.substring(0, 2) == '0x' ? ethAddress.substring(2, ethAddress.length) : ethAddress;

    /// Address should be size 20 bytes ie., 40 hex characters
    if (addrWithoutChecksum.length != 40) {
      throw "invalid ethereum address length";
    }

    addrWithoutChecksum = addrWithoutChecksum.toLowerCase();
    // Hash the address
    final List<int> codeUnits = addrWithoutChecksum.codeUnits;
    final Uint8List unit8List = Uint8List.fromList(codeUnits);
    final KeccakDigest keccakDigest = KeccakDigest(256);
    Uint8List hashedAddr = keccakDigest.process(unit8List);
    String hashedAddrInString = hex.encode(hashedAddr);

    // Generation of checksum
    String addrWithChecksum = "0x";
    for (int j = 0; j < addrWithoutChecksum.length; j++) {
      final int i = int.parse(hashedAddrInString[j], radix: 16);
      if (i > 7) {
        addrWithChecksum += addrWithoutChecksum[j].toUpperCase();
      } else {
        addrWithChecksum += addrWithoutChecksum[j];
      }
    }
    return addrWithChecksum;
  }
}
