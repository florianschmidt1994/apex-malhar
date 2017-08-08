package org.apache.apex.malhar.lib.utils.streamcodec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Test;

import org.apache.commons.lang.SerializationUtils;

import com.datatorrent.api.StreamCodec;
import com.datatorrent.lib.codec.JavaSerializationStreamCodec;
import com.datatorrent.netlet.util.Slice;

public class EncryptedStreamCodecTest
{

  @Test
  public void fromByteArray() throws Exception
  {
    SecretKey key = KeyGenerator.getInstance("AES").generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    String plaintext = "Lorem Ipsum";
    byte[] input = SerializationUtils.serialize(plaintext);
    byte[] encrypted = cipher.doFinal(input);

    StreamCodec<String> streamCodec = new EncryptedStreamCodec<>(new JavaSerializationStreamCodec<String>(), key);

    Assert.assertEquals(plaintext, streamCodec.fromByteArray(new Slice(encrypted)));
  }

  @Test
  public void fromByteArrayWithOffset() throws Exception
  {
    SecretKey key = KeyGenerator.getInstance("AES").generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    String plaintext = "Lorem Ipsum";

    byte[] input = SerializationUtils.serialize(plaintext);
    byte[] encrypted = cipher.doFinal(input);

    StreamCodec<String> streamCodec = new EncryptedStreamCodec<>(new JavaSerializationStreamCodec<String>(), key);

    byte[] large = new byte[encrypted.length * 2];
    System.arraycopy(encrypted, 0, large, 10, encrypted.length);
    Slice s = new Slice(large, 10, encrypted.length);

    Assert.assertEquals(plaintext, streamCodec.fromByteArray(s));
  }

  @Test
  public void toByteArrayWithOffset() throws Exception
  {
    SecretKey key = KeyGenerator.getInstance("AES").generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    String plaintext = "Lorem Ipsum";

    byte[] input = SerializationUtils.serialize(plaintext);
    byte[] encrypted = cipher.doFinal(input);

    StreamCodec<String> streamCodec = new EncryptedStreamCodec<>(new StreamCodec<String>()
    {
      @Override
      public Object fromByteArray(Slice fragment)
      {
        return SerializationUtils.deserialize(fragment.toByteArray());
      }

      @Override
      public Slice toByteArray(String o)
      {
        byte[] serialized = SerializationUtils.serialize(o);
        byte[] large = new byte[serialized.length * 2];
        System.arraycopy(serialized, 0, large, 10, serialized.length);
        return new Slice(large, 10, serialized.length);
      }

      @Override
      public int getPartition(String o)
      {
        return 0;
      }
    }, key);

    Assert.assertEquals(new Slice(encrypted), streamCodec.toByteArray(plaintext));
  }

  @Test
  public void getPartition() throws Exception
  {
    StreamCodec<String> streamCodec = new JavaSerializationStreamCodec<>();
    StreamCodec<String> encryptedStreamCodec = new EncryptedStreamCodec<>(streamCodec);

    int partition = streamCodec.getPartition("Lorem Ipsum");
    int encPartition = encryptedStreamCodec.getPartition("Lorem Ipsum");

    Assert.assertEquals(partition, encPartition);
  }

  @Test
  public void measurePerformanceEncryption()
  {
    final StreamCodec<String> streamCodecWithoutEncryption = new JavaSerializationStreamCodec<>();
    final StreamCodec<String> streamCodecWithEncryption = new EncryptedStreamCodec<>(streamCodecWithoutEncryption);

    final int numIterations = 1000000;

    measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithoutEncryption.toByteArray("Hello World");
        }
      }
    });

    measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithEncryption.toByteArray("Hello World");
        }
      }
    });

    long timeWithoutEncryption = measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithoutEncryption.toByteArray("Hello World");
        }
      }
    });

    long timeWithEncryption = measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithEncryption.toByteArray("Hello World");
        }
      }
    });

    double factor = (double)timeWithEncryption / (double)timeWithoutEncryption;

    // TODO: Remove output
    System.out.printf("%d iterations without encryption took %dns%n", numIterations, timeWithoutEncryption);
    System.out.printf("%d iterations  with  encryption took  %dns (%fx)%n", numIterations, timeWithEncryption, factor);

    Assert.assertTrue("Too much encryption overhead", factor < 1.01);

  }

  @Test
  public void measurePerformanceDecryption() throws Exception
  {
    SecretKey key = KeyGenerator.getInstance("AES").generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    final String plaintext = "Lorem Ipsum";
    final byte[] input = SerializationUtils.serialize(plaintext);
    final byte[] encrypted = cipher.doFinal(input);

    final StreamCodec<String> streamCodecWithoutEncryption = new JavaSerializationStreamCodec<>();
    final StreamCodec<String> streamCodecWithEncryption = new EncryptedStreamCodec<>(streamCodecWithoutEncryption, key);

    final int numIterations = 1000000;

    long timeWithoutEncryption = measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithoutEncryption.fromByteArray(new Slice(input));
        }
      }
    });

    long timeWithEncryption = measureNanos(new Runnable()
    {
      @Override
      public void run()
      {
        for (int i = 0; i < numIterations; i++) {
          streamCodecWithEncryption.fromByteArray(new Slice(encrypted));
        }
      }
    });

    double factor = (double)timeWithEncryption / (double)timeWithoutEncryption;

    // TODO: Remove output
    System.out.printf("%d iterations without encryption took %dns%n", numIterations, timeWithoutEncryption);
    System.out.printf("%d iterations  with  encryption took  %dns (%fx)%n", numIterations, timeWithEncryption, factor);

    Assert.assertTrue("Too much encryption overhead", factor < 1.01);

  }

  private long measureNanos(Runnable r)
  {
    long before = System.nanoTime();
    r.run();
    long after = System.nanoTime();
    return after - before;
  }

  @Test
  public void toByteArray() throws Exception
  {
    SecretKey key = KeyGenerator.getInstance("AES").generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    String plaintext = "Lorem Ipsum";
    byte[] input = SerializationUtils.serialize(plaintext);
    byte[] encrypted = cipher.doFinal(input);

    StreamCodec<String> streamCodec = new EncryptedStreamCodec<>(new JavaSerializationStreamCodec<String>(), key);

    Slice encryptedFromCodec = streamCodec.toByteArray(plaintext);

    Assert.assertEquals(new Slice(encrypted), encryptedFromCodec);
  }

}