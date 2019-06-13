package applet;

import javacard.framework.Util;
import javacard.security.RSAPublicKey;

class KeyHelper {

    static void init(RSAPublicKey key, byte[] buffer, short offset) {
        short expSize = Util.getShort(buffer, offset);
        short modSize = Util.getShort(buffer, (short) (offset + 2));

        key.setExponent(buffer, (short) (offset + 4), expSize);
        key.setModulus(buffer, (short) ((offset + 4) + expSize), modSize);
    }

}
