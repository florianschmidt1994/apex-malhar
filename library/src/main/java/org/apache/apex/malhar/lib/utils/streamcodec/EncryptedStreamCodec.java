package org.apache.apex.malhar.lib.utils.streamcodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.lang3.Validate;

import com.datatorrent.api.StreamCodec;
import com.datatorrent.lib.codec.KryoSerializableStreamCodec;
import com.datatorrent.netlet.util.Slice;

/**
 * This {@link StreamCodec} encrypts each tuple individually using AES encryption.
 * It is intended to be used as a decorator for any existing {@link StreamCodec}, such as
 * {@link KryoSerializableStreamCodec} <br/>
 * <br/>
 * This StreamCodec gets serialized and sent over the wire itself, so it can only be considered secure if the
 * underlying Hadoop RPC setup is secure.<br/>
 * <br/>
 * Example: <br/>
 * <br/>
 * StreamCodec<String> streamCodec = new EncryptedStreamCodec<>(new KryoSerializableStreamCodec<String>());<br/>
 * <br/>
 *
 * @param <T> Type of the object that gets serialized/deserialized with this code
 */
public class EncryptedStreamCodec<T> implements StreamCodec<T>, Serializable
{

  private final StreamCodec<T> streamCodec;
  private final String algorithm = "AES";
  private final String keystoreType = "JCEKS";

  private SecretKey key;
  private Cipher cipher;

  // Stores the current cypher mode (encrypt / decrypt)
  // This is used so that the mode does not need to be
  // set each time encrypt() / decrypt() is called
  private int mode;

  /**
   * Creates a new instance of EncryptedStreamCodec and creates a new secret key for encryption
   *
   * @param streamCodec The streamCodec to be used for serialization / deserialization
   */
  public EncryptedStreamCodec(StreamCodec<T> streamCodec)
  {
    final KeyGenerator generator;

    try {
      generator = KeyGenerator.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    this.key = generator.generateKey();
    this.streamCodec = streamCodec;
  }

  /**
   * Creates a new instance of EncryptedStreamCodec and uses an existing {@link SecretKey} for encryption
   *
   * @param streamCodec The streamCodec to be used for serialization / deserialization
   * @param key         The secretKey used for encryption. Must be an AES key
   */
  public EncryptedStreamCodec(StreamCodec<T> streamCodec, SecretKey key)
  {
    this.key = key;
    this.streamCodec = streamCodec;
  }

  public EncryptedStreamCodec(StreamCodec<T> streamCodec, Properties keystoreProperties)
  {
    this.streamCodec = streamCodec;
    this.loadKey(keystoreProperties);
  }

  @Override
  public Object fromByteArray(Slice slice)
  {
    final byte[] plaintext = decrypt(slice);
    return streamCodec.fromByteArray(new Slice(plaintext));
  }

  @Override
  public int getPartition(T o)
  {
    return streamCodec.getPartition(o);
  }

  @Override
  public Slice toByteArray(T o)
  {
    final Slice plaintext = streamCodec.toByteArray(o);
    final byte[] encrypted = encrypt(plaintext);
    return new Slice(encrypted);
  }

  private void createCipher()
  {
    if (this.cipher != null) {
      return;
    }

    try {
      this.cipher = Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new StreamCodecEncryptionException("Error creating cipher", e);
    }
  }

  private byte[] encrypt(Slice data)
  {
    try {
      this.createCipher();

      if (this.mode != Cipher.ENCRYPT_MODE) {
        this.mode = Cipher.ENCRYPT_MODE;
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
      }

      return this.cipher.doFinal(data.buffer, data.offset, data.length);
    } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
      throw new StreamCodecEncryptionException("Error encrypting data", e);
    }
  }

  private byte[] decrypt(Slice slice)
  {
    try {
      this.createCipher();

      if (this.mode != Cipher.DECRYPT_MODE) {
        this.mode = Cipher.DECRYPT_MODE;
        this.cipher.init(Cipher.DECRYPT_MODE, this.key);
      }
      return this.cipher.doFinal(slice.buffer, slice.offset, slice.length);
    } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
      throw new StreamCodecEncryptionException("Error decrypting data", e);
    }
  }

  private void loadKey(Properties keystoreProperties)
  {
    String name = keystoreProperties.getProperty("keystore.name");
    String type = keystoreProperties.getProperty("keystore.type");
    String password = keystoreProperties.getProperty("keystore.password");
    String keyAlias = keystoreProperties.getProperty("keystore.key.alias");
    String keyPassword = keystoreProperties.getProperty("keystore.key.password");

    Validate.notNull(name, "Name of keystore file cannot be null");
    Validate.notNull(type, "Type of keystore cannot be null");
    Validate.notNull(password, "Password for keystore cannot be null");
    Validate.notNull(keyAlias, "Alias for key cannot be null");
    Validate.notNull(keyPassword, "Password for key cannot be null");

    try {
      InputStream keystoreStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
      KeyStore keystore = KeyStore.getInstance(keystoreType);
      keystore.load(keystoreStream, password.toCharArray());
      this.key = (SecretKey)keystore.getKey(keyAlias, keyPassword.toCharArray());
      Validate.notNull(this.key, "Key with name '" + name + "' could not be loaded");
    } catch (KeyStoreException |
      IOException |
      CertificateException |
      NoSuchAlgorithmException |
      UnrecoverableKeyException e) {

      throw new StreamCodecEncryptionException("An error occurred while loading keys from keystore", e);
    }
  }
}
