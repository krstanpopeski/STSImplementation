import javax.crypto.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;

public class Certificate {

    private String name;
    private PublicKey publicKey;
    private BigInteger g;
    private BigInteger p;
    private byte [] signature;

    public Certificate(String name, PublicKey publicKey, BigInteger g, BigInteger p, PrivateKey secretKey){
        this.name = name;
        this.publicKey = publicKey;
        this.g = g;
        this.p = p;

        try {
            this.signature = Sign(secretKey);
        } catch (Exception e){
            System.out.println(e.getMessage());
        }

    }

    private byte [] Sign(PrivateKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte [] name = this.name.getBytes();
        byte [] publicKey = this.publicKey.getEncoded();
        byte [] g = this.g.toByteArray();
        byte [] p = this.p.toByteArray();
        ByteBuffer buffer = ByteBuffer.allocate(name.length + publicKey.length + g.length + p.length);
        buffer.put(name).put(publicKey).put(g).put(p);
        byte [] concatData = buffer.array();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte [] hashed = digest.digest(concatData);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);

        return cipher.doFinal(hashed);

    }

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }

    public byte[] getSignature() {
        return signature;
    }
}
