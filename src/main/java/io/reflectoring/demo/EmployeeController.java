package io.reflectoring.demo;


import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Security;
import java.util.Objects;

@RestController
class EmployeeController {

    public EmployeeController(){
        Security.addProvider(new BouncyCastleProvider());
    }

    // Aggregate root
    // tag::get-aggregate-root[]
    @GetMapping("/u")
    String all(String s) {
        if (Objects.equals(s, "")){
            return "";
        }
        X9ECParameters c2pnb368w1 = X962NamedCurves.getByName("c2pnb368w1");
//        String s = args[0];
//        System.out.println(s);
//        s="032e840eedd1f5bc361aa71545b562ad675d2268bfe2ec496f474bc419ae0aa5c3fab249b5f34aa531b92167bdfca4";
        ECPoint ecPoint = c2pnb368w1.getCurve().decodePoint(hexStringToByteArray(s));
//        System.out.println(getHex(ecPoint.getEncoded(false)));
        return getHex(ecPoint.getEncoded(false));
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    private static final String    HEXES    = "0123456789ABCDEF";

    static String getHex(byte[] raw) {
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }
}