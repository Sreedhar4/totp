package com.totp.totp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;


/**
 * https://datatracker.ietf.org/doc/html/rfc6238
 * https://datatracker.ietf.org/doc/html/rfc4226
 */
public class TOTPGenerator {
    private static final int TIME_STEP_30 = 30;
    private static final String HMAC_SHA1 = "HmacSHA1";

    private Mac mac;

    public TOTPGenerator(){
        try {
            this.mac = Mac.getInstance(HMAC_SHA1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(System.out);
        }
    }

    public static void main(String[] args) {
        
        try {
            TOTPGenerator totp = new TOTPGenerator();

            String secretString = "TESTpasswordTESTpasswordT";
            String secret = new String(new Base32().encode(secretString.getBytes()));// This is configured in authenticator app
            System.out.println("Base32 ==> " + secret);

            System.out.println(String.format("===> %06d <===",totp.getOTP(secretString, Instant.now())));

        } catch (IllegalStateException e) {
            e.printStackTrace();
        } 
        
    }

    public int getOTP(String secret,Instant instant) {
        byte[] counterBytes  = ByteBuffer.allocate(8)
                                    .putLong(0, getTimeStep(instant))
                                    .array();
        ByteBuffer hmac = getHMAC(secret, counterBytes);
        printByteArrayAsHex("Hmac as hex ==> ",hmac.array());
        final int offset = hmac.get(hmac.array().length - 1) & 0xf;
        System.out.println("Offset ==> " + offset);
        return ((hmac.getInt(offset) & 0x7FFFFFFF) % 1000000);
    }

    private void printByteArrayAsHex(String marker, byte[] hmac) {
        StringBuffer sbuff = new StringBuffer();
        for(int i=0;i<hmac.length;i++){
            int b = hmac[i] & 0xFF;
            sbuff.append(Integer.toHexString(b));
        }
        System.out.println(marker + sbuff);
    }

    public ByteBuffer getHMAC(String secret, byte[] counter) {
        try {
            this.mac.init(getKey(secret));
            System.out.println("Mac kength ==> " + mac.getMacLength());
            return ByteBuffer.wrap( mac.doFinal(counter));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Key getKey(String secret) {
        if(null==secret){
            return null;
        }
        byte[] keyBytes =  secret.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, HMAC_SHA1);
        printByteArrayAsHex("Key Bytes ==> ", secretKeySpec.getEncoded());
        // + " "+ secretKeySpec.getEncoded().length + " bytes <==");
        return secretKeySpec;
    }

    public static long getTimeStep(Instant instant) {
        System.out.println(instant);
        long counter = instant.toEpochMilli() / Duration.ofSeconds(TIME_STEP_30).toMillis();
        System.out.println("Time step ==> " + counter);
        return counter;
    }

    public String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16];
        random.nextBytes(bytes);
        Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String token = encoder.encodeToString(bytes);
        System.out.println(token);
        return token;
    }
}
