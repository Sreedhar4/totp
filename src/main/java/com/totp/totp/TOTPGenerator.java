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
import javax.crypto.ShortBufferException;
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
    private ByteBuffer buffer;

    public TOTPGenerator(){
        try {
            this.mac = Mac.getInstance(HMAC_SHA1);
            this.buffer = ByteBuffer.allocate(mac.getMacLength());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(System.out);
        }
    }

    public static void main(String[] args) {
        
        try {
            TOTPGenerator totp = new TOTPGenerator();

            String secretString = "TESTpasswordTESTpasswordT";
            String secret = new String(new Base32().encode(secretString.getBytes()));// This is configured in authenticator app
            System.out.println("Secret of Authenticator APP ==> " + secret);

            System.out.println(String.format("===> %06d <===",totp.getOTP(secretString, Instant.now().minusSeconds(30))));
            System.out.println(String.format("===> %06d <===",totp.getOTP(secretString, Instant.now())));
            System.out.println(String.format("===> %06d <===",totp.getOTP(secretString, Instant.now().plusSeconds(30))));

        } catch (IllegalStateException e) {
            e.printStackTrace();
        } 
        
    }

    /**
     * The buffer is 20 bytes long, we clear the buffer before reuse
     * Put the counter at index zero through 8, as the the time steps is long
     * @param secret
     * @param instant
     * @return
     */
    public int getOTP(String secret,Instant instant) {
        this.buffer.clear();
        this.buffer.putLong(0,  getTimeStep(instant));
        getHMAC(secret);
        // printByteArrayAsHex("Hmac as hex ==> ",this.buffer.array());
        final int offset = this.buffer.get(this.buffer.array().length - 1) & 0xf;
        //System.out.println("Offset ==> " + offset);
        return ((this.buffer.getInt(offset) & 0x7FFFFFFF) % 1000000);
    }

    private void printByteArrayAsHex(String marker, byte[] hmac) {
        StringBuffer sbuff = new StringBuffer();
        for(int i=0;i<hmac.length;i++){
            int b = hmac[i] & 0xFF;
            sbuff.append(Integer.toHexString(b));
        }
        //System.out.println(marker + sbuff);
    }

    /**
     * HMAC is calculated for 8 bytes which holds the time step using the secret
     * calculated hmac is placed in the same buffer
     * @param secret
     */
    private void getHMAC(String secret) {
        try {
            this.mac.init(getKey(secret));
            byte[] array = this.buffer.array();
            this.mac.update(array, 0, 8);
            mac.doFinal(array, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }

    private Key getKey(String secret) {
        if(null==secret){
            return null;
        }
        byte[] keyBytes =  secret.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, HMAC_SHA1);
        printByteArrayAsHex("Key Bytes ==> ", secretKeySpec.getEncoded());
        return secretKeySpec;
    }

    public long getTimeStep(Instant instant) {
       // System.out.println(instant);
        long counter = instant.toEpochMilli() / Duration.ofSeconds(TIME_STEP_30).toMillis();
        //System.out.println("Time step ==> " + counter);
        return counter;
    }

    public String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String token = encoder.encodeToString(bytes);
        System.out.println(token);
        return token;
    }
}
