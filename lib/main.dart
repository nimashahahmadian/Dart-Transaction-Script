import 'dart:convert';
import 'dart:math';

import 'dart:typed_data';
import 'package:codetest/model/hash_authentication.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import 'package:rlp/rlp.dart';
import 'package:rlp/src/address.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:web3dart/crypto.dart';

void main() async {
  var to = '42cAB71dc20BdC5ffeab2112F721eE0Bf55e72E1';
  String s = '';
  String r = '';
  int nounce = 16;
  double amount = 0.0001;
  double gasprice = 2; //gwei
  int chainID = 80001;
  int recID = 0;
  var maxValueForS = BigInt.parse('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', radix: 16);
  var treshHoldForS = BigInt.parse('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', radix: 16);
  String signed =
      '3045022052D572F2B75099FD25E9AAD305586771005595DCEE04B2BFE65D62C1F2DA330A02210093E8257D0E51D7234489A75F0C6D724A08279ACAA716F85FD408CF8AB0EDE577';
  String signersPublicKey = '9da10855a89acc92599190b133faec5b484ac780b3e03e479fd7743205748636';
  var transaction = {
    "Nonce": nounce,
    "Gas Price": (gasprice * pow(10, 9)).toInt(),
    "Gas Limit": 21000,
    "To Address": BigInt.parse(to, radix: 16),
    "Amount": (amount * pow(10, 18)).toInt(),
    "data": '',
    'v': chainID,
    "r": r,
    "s": s
  };
  var transactioneip1559 = {
    "chainID": chainID,
    "Nonce": nounce,
    "maxpriorityfeepergas": (gasprice * pow(10, 9)).toInt(),
    "maxfeepergas": (gasprice * pow(10, 9)).toInt() + 40,
    "Gas Limit": 21000,
    "To Address": BigInt.parse(to, radix: 16),
    "Amount": (amount * pow(10, 18)).toInt(),
    "data": '',
    'accesslist': List.empty(),
    // 'v': 80001,
    "v": recID,
    "r": r,
    "s": s
  };

  List list = List.from(transaction.values);
  List listEip1559 = List.from(transactioneip1559.values);
  var rlp = Rlp.encode(list);
  var rlpEip1559 = Rlp.encode(listEip1559);
  var rlphash = AuthenticationHash.hashKeccak256(rlp);
  var rlphashEip1559 = AuthenticationHash.hashKeccak256(rlpEip1559);
  print('legacy hashMsg: $rlphash');
  print('eip1559 hashMsg: $rlphashEip1559');
  var rLen = HexUtils.hexStringToByteArray(signed.substring(6, 8));
  r = signed.substring(8, 8 + rLen[0] * 2);
  s = signed.substring(12 + rLen[0] * 2);
  transaction['r'] = BigInt.parse(r, radix: 16);
  transactioneip1559['r'] = BigInt.parse(r, radix: 16);

  if (BigInt.parse(s, radix: 16) <= treshHoldForS) {
    transaction['s'] = BigInt.parse(s, radix: 16);
    transactioneip1559['s'] = BigInt.parse(s, radix: 16);
  } else {
    transaction['s'] = maxValueForS - BigInt.parse(s, radix: 16);
    transactioneip1559['s'] = maxValueForS - BigInt.parse(s, radix: 16);
    // print('recid changed here');
    // recID = (1 + recID) % 2;
  }

  for (int i = 0; i < 2; i++) {
    var sig = MsgSignature(transaction['r'] as BigInt, transaction['s'] as BigInt, 27 + i);
    try {
      String pk = HexUtils.byteArrayToHexString(ecRecover(HexUtils.hexStringToByteArray(rlphash), sig));
      if (pk.substring(0, 64) == signersPublicKey) {
        print(pk);
        print(i);
        recID = (recID + i) % 2;
        print(recID);
      }
      //recID=i%2
    } catch (e) {
      print('Recovery id is not ${27 + i}');
    }
  }
  for (int i = 0; i < 2; i++) {
    var sigeip1559 = MsgSignature(transactioneip1559['r'] as BigInt, transactioneip1559['s'] as BigInt, 27 + i);
    try {
      String pk = HexUtils.byteArrayToHexString(ecRecover(HexUtils.hexStringToByteArray(rlphashEip1559), sigeip1559));
      if (pk.substring(0, 64) == signersPublicKey) {
        print(pk);
        print(i);
        recID = recID + (i % 2);
        print(recID);
      }
      //recID=i%2
    } catch (e) {
      print('Recovery id is not ${27 + i}');
    }
  }
  transaction['v'] = chainID * 2 + 35 + recID;
  transactioneip1559['v'] = recID;

  list = List.from(transaction.values);
  listEip1559 = List.from(transactioneip1559.values);
  var signedRlp = Rlp.encode(list);
  var signedRlpEip1559 = Rlp.encode(listEip1559);
  print("legacy transaction : ${HexUtils.byteArrayToHexString(signedRlp)}");
  print("eip1559 transaction : 0x02${HexUtils.byteArrayToHexString(signedRlpEip1559)}");
}

class HexUtils {
  static String byteArrayToHexString(Uint8List buffer) {
    String result = "";
    for (int i = 0; i < buffer.length; i++) {
      if (buffer[i] < 16) {
        result = result + "0" + buffer[i].toRadixString(16);
      } else {
        result += buffer[i].toRadixString(16);
      }
    }
    return result;
  }

  static String intToHexString(int buffer, int buffersize) {
    String result = buffer.toRadixString(16);
    while (result.length % buffersize != 0) {
      result = "0" + result;
    }
    return result;
  }

  static BigInt hexStringToBigInt(String hex) {
    return BigInt.parse(hex, radix: 16);
  }

  static Uint8List hexStringToByteArray(String hex) {
    Uint8List buffer = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < buffer.length; i++) {
      buffer[i] = int.parse(hex.substring(i * 2, (i + 1) * 2), radix: 16);
    }
    return buffer;
  }
}
