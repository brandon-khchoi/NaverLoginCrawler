package com.kyuth.naver.login.crawler.common;

import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.SecureRandom;


@Slf4j
public class JsRsaEncrypt {
    public int _EXPONENT;
    public BigInteger _MODULUS;
    public boolean _CAN_ENCRYPT;

    private final BigInteger _ZERO = new BigInteger("0");

    /**
     * javascript RSA 암호화 java 포팅
     *
     * @param modulus  16진수 BigInteger
     * @param exponent 16진수 int
     * @author brandon
     * @since 2021-07-27
     */
    public JsRsaEncrypt(BigInteger modulus, int exponent) {
        this._MODULUS = modulus;
        this._EXPONENT = exponent;
        this._CAN_ENCRYPT = (_MODULUS != null && !_MODULUS.equals(_ZERO) && _EXPONENT != 0);
    }

    /**
     * javascript RSA 암호화 java 포팅
     *
     * @param modulus  16진수 String
     * @param exponent 16진수 String
     * @author brandon
     * @since 2021-07-27
     */
    public JsRsaEncrypt(String modulus, String exponent) {
        this._MODULUS = new BigInteger(modulus, 16);
        this._EXPONENT = Integer.parseInt(exponent, 16);
        this._CAN_ENCRYPT = (_MODULUS != null && !_MODULUS.equals(_ZERO) && _EXPONENT != 0);
    }

    public int getBlockSize() {
        return (_MODULUS.bitLength() + 7) / 8;
    }

    public BigInteger doPublic(BigInteger x) {
        if (this._CAN_ENCRYPT) {
            return x.modPow(new BigInteger(this._EXPONENT + ""), this._MODULUS);
        }
        return _ZERO;
    }

    public String encrypt(String text) throws Exception {

        BigInteger pkcs1pad2Result = new BigInteger(this.pkcs1pad2(text.getBytes(), this.getBlockSize()));
        if (pkcs1pad2Result.equals(_ZERO)) {
            return null;
        }

        BigInteger doPublicResult = this.doPublic(pkcs1pad2Result);
        if (doPublicResult.equals(_ZERO)) {
            return null;
        }

        String result = doPublicResult.toString(16);
        int e = (this._MODULUS.bitLength() + 7 >> 3 << 1) - result.length();
        while (e-- > 0) {
            result = "0" + result;
        }

        return result;
    }

    private byte[] pkcs1pad2(byte[] data, int blockSize) throws Exception {
        if (blockSize < data.length + 11) {
            throw new Exception("RSA Encrypt: Message is to big!");
        }
        byte[] result = new byte[blockSize];
        int dataSize = data.length - 1;
        while (dataSize >= 0 && blockSize > 0) {
            result[--blockSize] = data[dataSize--];
        }
        result[--blockSize] = 0;
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[1];
        while (blockSize > 2) {
            bytes[0] = 0;
            while (bytes[0] == 0) {
                secureRandom.nextBytes(bytes);
            }
            result[--blockSize] = bytes[0];
        }
        result[--blockSize] = 2;
        result[--blockSize] = 0;

        return result;
    }

}
