import 'dart:convert';
import 'dart:math';

import 'dart:typed_data';
import 'package:codetest/model/hash_authentication.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import 'package:rlp/rlp.dart';
import 'package:rlp/src/address.dart';

void main() async {
  var to = '42cAB71dc20BdC5ffeab2112F721eE0Bf55e72E1';
  String s = '';
  String r = '';
  int nounce = 172;
  double amount = 0.0001;
  double gasprice = 29; //gwei
  int chainID = 5;
  int recID = 1;
  var maxValueForS = BigInt.parse('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', radix: 16);
  var treshHoldForS = BigInt.parse('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', radix: 16);
  String signed =
      '304402201D568D2E7162E711FEF77AD2773B0FA8B619D0FFBB297CCB8FC02745C57FFC1902200A18DCD9F6DBFB0F81A4C5EB807F023025287A37CF8139D5DB70874AC4823D29';
  var apiUrl = "https://polygon-rpc.com"; //Replace with your API
  "https://gasstation-mainnet.matic.network/v2";
  header() => {"Content-Type": "application/json"};
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
    "maxpriorityfeepergas": (1 * pow(10, 9)).toInt(),
    "maxfeepergas": (gasprice * pow(10, 9)).toInt(),
    "Gas Limit": 9000000,
    "To Address": BigInt.parse(to, radix: 16),
    "Amount": (amount * pow(10, 18)).toInt(),
    "data": '',
    'accesslist': List.empty(),
    // 'v': 80001,
    "v": 1,
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

  r = signed.split('022')[1].substring(1);
  s = signed.split('022')[2].substring(1);

  transaction['r'] = BigInt.parse(r, radix: 16);
  transactioneip1559['r'] = BigInt.parse(r, radix: 16);

  if (BigInt.parse(s, radix: 16) < treshHoldForS) {
    transaction['s'] = BigInt.parse(s, radix: 16);
    transactioneip1559['s'] = BigInt.parse(s, radix: 16);
  } else {
    transaction['s'] = maxValueForS - BigInt.parse(s, radix: 16);
    transactioneip1559['s'] = maxValueForS - BigInt.parse(s, radix: 16);
  }
  transaction['v'] = chainID * 2 + 35 + recID;

  list = List.from(transaction.values);
  listEip1559 = List.from(transactioneip1559.values);
  var signedRlp = Rlp.encode(list);
  var signedRlpEip1559 = Rlp.encode(listEip1559);
  print("legacy transaction : ${HexUtils.byteArrayToHexString(signedRlp)}");
  print("eip1559 transaction : 0x02${HexUtils.byteArrayToHexString(signedRlpEip1559)}");

  print(BigInt.parse(s, radix: 16) > treshHoldForS);
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
