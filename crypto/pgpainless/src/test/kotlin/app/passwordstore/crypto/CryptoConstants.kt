/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

object CryptoConstants {
  const val KEY_PASSPHRASE = "hunter2"
  const val PLAIN_TEXT = "encryption worthy content"
  const val AEAD_KEY_PASSPHRASE = "Password"
  val AEAD_ENCRYPTED_TEXT =
    """
    -----BEGIN PGP MESSAGE-----

    hQIMA3mxTrDxxx8VAQ/+JZAc6+bPqReHh1lfcm0Spy6PGt+2rtDyDkQ1GBfQ2kHW
    ZBR7Hi+4NIdK6H60e+VbNpvEYoMYwNHUi67NDTUFTADrv+BdlOqPzT+4yuFAyLKU
    qX3EZUQwKn0Y9kbpBal5D2QKmgiG3jS3weKs82xVdzfH6m3LtsAjjSXK9SUv/HtN
    DJloqvpqc2FcpDLvwOMbMPw0/uaDrcexGOWrhm/SxX6A0kkPHlfLpMVVpQtzNBTP
    gtm6epNam1q+xRHPdSHttV10f4WdF4ru8j2W2cBTg5o2YYGGqbWkewKOEmNsPM+a
    GA/fJ7WnfmSXeE82PsbVQL8Thtad30U0zvcGhktQPQZqBspj6J/D59kQStgEVdcL
    RbbQ8jhNyGFUVcUlXIi2d/eQ/d300JLU2jwipG+OvJz340ducfRuReUFX+dNLs0i
    yW7nNmkZ41+sga+YK/HITq+vJSO7/UzeVxTIzRrHyr3AA9IwDQqoosxXaLlDdcDv
    VbvUxFgfSdIHBRgTsEiSLrbzPdGp7fIEu2kY8rGvzVG8AzQcxCt+/2v99fmHC0wo
    sgrfIJrYg+xNUeMw9qdC2DMksRN1lkiX767aCIHV88/XUVxQEg/Jbjv66ENfjA2j
    frBnd6mCqT4DAFXEABC3fcrScOPmTO8UgV7L+7wCNxXsmlSrG/TmZNdUGs3+tujS
    wD0BpoeJOiZ13UnIQW+8FE//FTAs91haFkR+zjIKpR1w2aYkGXzZtAUcdjZU5XYX
    6MrV+tZSfyIytk1SedddanV681J0mYnlrga9mbTLUF+zuY4LjG/H60alf0gqJBdL
    /shlV7o+10+HxytUUR1HwZGD19gw858iqDWq4zgh/boSjzE+a4RGt+b8h7ypxf1Q
    /pp4XpKUjVkzTVRRjEJR5X76WUfUshGdgli77E0UGiR1FnaWEQH3ElFUVj0anEy7
    G9hM2oNUFgRMG2zMLQYnqU2JF3QfZ/275cYbSyn2Gc3fhiO8lUzme/LSydrQxLLs
    a9lzB0qeaiJCo1Xgd2qm
    =WpO6
    -----END PGP MESSAGE-----
    """
  const val KEY_NAME = "John Doe"
  const val KEY_EMAIL = "john.doe@example.com"
  const val KEY_ID = 0x08edf7567183ce27
}
