import 'dart:convert';
import 'dart:typed_data';
import "package:pointycastle/export.dart";

var blockSize = 16;
var iv = '2R023@d!(2n#4_6@';

var ivBytes = utf8.encode(iv) as Uint8List;

class AuthenticationHash {
  static String hashSha256(value) {
    final sha256 = SHA256Digest();
    Uint8List hashsha256 = sha256.process(value);
    String stringHashSha256 = bin2hex(hashsha256);
    return stringHashSha256.toUpperCase();
  }

  static String hashDoubleSha256(value) {
    final sha256 = SHA256Digest();
    Uint8List firstHash = sha256.process(utf8.encode(value) as Uint8List);
    Uint8List secondHash = sha256.process(firstHash);
    String stringSecondHash = bin2hex(secondHash);
    return stringSecondHash.toUpperCase();
  }

  static String hashKeccak256(value) {
    final keccak256 = KeccakDigest(256);
    Uint8List hashsha256 = keccak256.process(value);
    String stringHashSha256 = bin2hex(hashsha256);
    return stringHashSha256.toUpperCase();
  }

  static String bin2hex(Uint8List bytes, {String? separator, int? wrap}) {
    var len = 0;
    final buf = StringBuffer();
    for (final b in bytes) {
      final s = b.toRadixString(16);
      if (buf.isNotEmpty && separator != null) {
        buf.write(separator);
        len += separator.length;
      }

      if (wrap != null && wrap < len + 2) {
        buf.write('\n');
        len = 0;
      }

      buf.write('${(s.length == 1) ? '0' : ''}$s');
      len += 2;
    }
    return buf.toString();
  }

  static Uint8List pad(Uint8List src, blocksize) {
    var pad = PKCS7Padding();
    pad.init(null);
    int padLength = src.length % blocksize == 0 ? 0 : blocksize - (src.length % blocksize);
    var out = Uint8List(src.length + padLength)..setAll(0, src);
    if (padLength != 0) {
      pad.addPadding(out, src.length);
    }
    return out;
  }

  static Uint8List unpad(Uint8List src) {
    var pad = PKCS7Padding();
    pad.init(null);
    int padLength = pad.padCount(src);
    int len = src.length - padLength;
    return Uint8List(len)..setRange(0, len, src);
  }

  static Uint8List _processBlocks(BlockCipher cipher, Uint8List inp) {
    var out = Uint8List(inp.lengthInBytes);
    for (var offset = 0; offset < inp.lengthInBytes;) {
      var len = cipher.processBlock(inp, offset, out, offset);
      offset += len;
    }
    return out;
  }

  static Future<String> encryptAES256CBC(String message, Uint8List key) async {
    var messageBytes = utf8.encode(message) as Uint8List;
    var paddedMsg = pad(messageBytes, blockSize);
    var cipher = AESEngine();
    var params = KeyParameter(key);
    var cbcParams = ParametersWithIV(params, ivBytes);
    var cbcCipher = CBCBlockCipher(cipher);
    cbcCipher.init(true, cbcParams);
    var encrypted = _processBlocks(cbcCipher, paddedMsg);
    return base64Encode(encrypted);
  }

  static String decryptAES256CBC(String encrypted, Uint8List key) {
    var cipher = AESEngine();
    var params = KeyParameter(key);
    var encryptedBytes = base64Decode(encrypted);
    var cbcParams = ParametersWithIV(params, ivBytes);
    var cbcCipher = CBCBlockCipher(cipher);
    cbcCipher.init(false, cbcParams);
    print('wil decrypt bytes');
    print('length is ${encryptedBytes.length}');
    var paddedText = _processBlocks(cbcCipher, encryptedBytes);
    print(String.fromCharCodes(paddedText));
    print('unpading');
    var textBytes = unpad(paddedText);
    return String.fromCharCodes(textBytes);
  }
}
