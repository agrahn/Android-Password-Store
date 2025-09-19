/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Code taken from BouncyCastle-1.81 file of the same name
 *
 */

package app.passwordstore.crypto;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;

/**
 * Calculator for the EC based KDF algorithm described in RFC 6637
 */
class RFC6637KDFCalculator
{
    private final PGPDigestCalculator digCalc;
    private final int keyAlgorithm;

    public RFC6637KDFCalculator(PGPDigestCalculator digCalc, int keyAlgorithm)
    {
        this.digCalc = digCalc;
        this.keyAlgorithm = keyAlgorithm;
    }

    public byte[] createKey(byte[] secret, byte[] userKeyingMaterial)
        throws PGPException
    {
        try
        {
            // RFC 6637 - Section 8
            return KDF(digCalc, secret, getKeyLen(keyAlgorithm), userKeyingMaterial);
        }
        catch (IOException e)
        {
            throw new PGPException("Exception performing KDF: " + e.getMessage(), e);
        }
    }

    // RFC 6637 - Section 7
    //   Implements KDF( X, oBits, Param );
    //   Input: point X = (x,y)
    //   oBits - the desired size of output
    //   hBits - the size of output of hash function Hash
    //   Param - octets representing the parameters
    //   Assumes that oBits <= hBits
    //   Convert the point X to the octet string, see section 6:
    //   ZB' = 04 || x || y
    //   and extract the x portion from ZB'
    //         ZB = x;
    //         MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
    //   return oBits leftmost bits of MB.
    private static byte[] KDF(PGPDigestCalculator digCalc, byte[] ZB, int keyLen, byte[] param)
        throws IOException
    {
        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(0x00);
        dOut.write(0x00);
        dOut.write(0x00);
        dOut.write(0x01);
        dOut.write(ZB);
        dOut.write(param);

        byte[] digest = digCalc.getDigest();

        byte[] key = new byte[keyLen];

        System.arraycopy(digest, 0, key, 0, key.length);

        return key;
    }

    private static int getKeyLen(int algID)
        throws PGPException
    {
        switch (algID)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            return 16;
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            return 24;
        case SymmetricKeyAlgorithmTags.AES_256:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return 32;
        default:
            throw new PGPException("unknown symmetric algorithm ID: " + algID);
        }
    }
}
