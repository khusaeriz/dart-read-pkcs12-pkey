import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

typedef pkcs12_read_func = Pointer<Utf8> Function(Pointer<Utf8> path, Pointer<Utf8> password);

main() {
  print(readPKCS12File('./pkcs_library/devel-november.p12', '1234'));
}

String readPKCS12File(String file, String password) {
  var libPath = './pkcs_library/libpkcs12.so';
  if (Platform.isMacOS) libPath = './structs_library/structs.dylib';
  if (Platform.isWindows) libPath = 'structs_library\structs.dll';

  final dylib = DynamicLibrary.open(libPath);
  final pkcs12readPointer = 
    dylib.lookup<NativeFunction<pkcs12_read_func>>('read_pkcs12_from_file');
  final pkcs12read = pkcs12readPointer.asFunction<pkcs12_read_func>();

  var read = pkcs12read(Utf8.toUtf8(file), Utf8.toUtf8(password));
  var result = Utf8.fromUtf8(read);

  return result;
}