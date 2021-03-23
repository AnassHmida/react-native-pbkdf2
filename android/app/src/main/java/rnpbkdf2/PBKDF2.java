package rnpbkdf2;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;


import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 extends ReactContextBaseJavaModule {



    public PBKDF2(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static String derivationKey(String pwd, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt.getBytes(), 1000, 384);
        byte[] key = factory.generateSecret(spec).getEncoded();
        return bytesToHex(key);
    }

    @Override
    public String getName() {
        return "PBKDF2";
    }

    @ReactMethod
    public void derivationKey(String pwd, String salt, Integer iterations, Promise promise) {
        try {
            String strs = derivationKey(pwd, salt);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }
}