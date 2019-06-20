package applet;

import javacard.framework.Util;
import javacard.security.RSAPublicKey;

class KeyHelper {

    /**
     * Initialize the given RSA public key using the data inside the given buffer at the given offset.
     *
     * @param key    to initialize.
     * @param buffer containing data needed for initialization.
     * @param offset where the initialization data starts in the buffer.
     */
    static void init(RSAPublicKey key, byte[] buffer, short offset) {
        short expSize = Util.getShort(buffer, offset);
        short modSize = Util.getShort(buffer, (short) (offset + 2));

        key.setExponent(buffer, (short) (offset + 4), expSize);
        key.setModulus(buffer, (short) ((offset + 4) + expSize), modSize);
    }

}
