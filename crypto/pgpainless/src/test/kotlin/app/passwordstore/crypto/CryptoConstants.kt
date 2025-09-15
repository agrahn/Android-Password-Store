/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

object CryptoConstants {
  const val KEY_PASSPHRASE = "hunter2"
  const val KEY_PASSPHRASE_ALICE = "12345678"
  const val KEY_PASSPHRASE_BOBBY = "asdfghjk"

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
    """.trimIndent()
  const val KEY_NAME = "John Doe"
  const val KEY_EMAIL = "john.doe@example.com"
  const val KEY_ID = 0x08edf7567183ce27

  val HELLO_CLEAR_TEXT = "Hello World!\n"
  val HELLO_ENCRYPTED_TEXT =
    """
    -----BEGIN PGP MESSAGE-----

    hQIMA3yZAYfOcsjkAQ/9GRK0yzIxjEhPnZMXe23+rXVBN1mSVai+eCJcYJkZQVH3
    i7/XTPg8i8DRm06W7gK+soOTGNTdQrEs8YXaG1OJX+RrFaW8wTt77ASqSCSDT36a
    ww/8l4Fqq96j2i5IiBajbFmmNyIxbE59ZxcWa9RiY2KMDaD6hbVtj8jTJNUBN44g
    UUVSulr4ZEJCc7bMGHsTWjmU1rnXfD/4R6ynlLN9tohIl3kH7ghAyOeXTTR7NeG/
    eJJFDp2hgk+PnYiO8GAbZRpug1Fl157MNwbh0GJrWzwkENfTYgO1YXZZspmKuGM9
    9JQQPgVcVn66zo0eWhESq5w+DqkKjamcVYvuAlYgTc6+Z9ae4b32AJ1kUu3bWQx6
    3bwNyQHVE9wXhu2BHq6y+c6G9f63v+wfdt2p828rtFB33wyb+/1n0pH9bnYd6KLi
    M1pftuHfGSsuJr5j6ivW9nEWI6LF0VBP6axYh3ao6JQw0STYNm2PCmggpQX8A+Tk
    1UYWbHmES/3BOVcnjM8bP9XYWjBrNaXwnLfKv9/t7UwVDbX7MYUMs0gAVSBzkRCn
    /4kkQ/p6ZZn253ro9pA0hYP2/qL8d2zngi3oQsCAkzxQlnHL9rHbYT+ffowvn3bK
    8iz0xnKvinLCuHk+mfAptCIn9oNdwUvE/Wk/o4fe7ZRSikX/VA61AynGa8JImGfS
    TwH26wjbaOHbkHZ8Feuh52+fU8D+PoZ92MrQ6HP3LjKjSmmoqHLLrBJyCz/ichYg
    DNqbZW2NmB6aJkr46rifUc0JmturPw713yRF78kmhVA=
    =gWDu
    -----END PGP MESSAGE-----
    """.trimIndent()
  val HELLO_SESSIONKEY_DATA = "0943C92A7EEF59AA014D2FDC54767D7DA7126CA7DF1C94B71769B6F45629B3A69D"
}
