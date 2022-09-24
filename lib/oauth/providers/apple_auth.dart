import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_oauth/oauth/models/result.dart';
import 'package:flutter_oauth/oauth/models/oauth_user.dart';
import 'package:flutter_oauth/oauth/providers/oauth_provider_contract.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

typedef AppleSign = Future<AuthorizationCredentialAppleID> Function(
    String nonce);

class AppleAuthProvider implements IOauthProvider {
  final AppleSign _signInWithApple;
  final Future<bool> Function() _isAvailable;

  const AppleAuthProvider({
    AppleSign? signInWithApple,
    Future<bool> Function()? isAvailable,
  })  : _signInWithApple = signInWithApple ?? _appleSignIn,
        _isAvailable = isAvailable ?? _appleIsAvailable;

  @override
  Future<Result<OAuthUser>> login() async {
    if (!await _isAvailable()) {
      return Result<OAuthUser>.failure(['Apple Sign In is not available']);
    }

    final rawNonce = generateNonce();
    final nonce = _sha256ofString(rawNonce);

    try {
      final AuthorizationCredentialAppleID appleCredentail =
          await _signInWithApple(nonce);
      return Result<OAuthUser>.success(
        OAuthUser(
          email: appleCredentail.email!,
          firstName: appleCredentail.givenName!,
          lastName: appleCredentail.familyName!,
        ),
      );
    } catch (e) {
      return Result<OAuthUser>.failure(['Apple Sign In is not available']);
    }
  }

  @override
  Future<bool> logout() async => true;

  static Future<AuthorizationCredentialAppleID> _appleSignIn(String nonce) =>
      SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        nonce: nonce,
      );

  static Future<bool> _appleIsAvailable() => SignInWithApple.isAvailable();

  /// Returns the sha256 hash of [input] in hex notation.
  String _sha256ofString(String input) {
    final List<int> bytes = utf8.encode(input);
    final Digest digest = sha256.convert(bytes);
    return digest.toString();
  }
}
