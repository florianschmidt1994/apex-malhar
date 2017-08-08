package org.apache.apex.malhar.lib.utils.streamcodec;

class StreamCodecEncryptionException extends RuntimeException {
  public StreamCodecEncryptionException()
  {
  }

  public StreamCodecEncryptionException(String message)
  {
    super(message);
  }

  public StreamCodecEncryptionException(String message, Throwable cause)
  {
    super(message, cause);
  }

  public StreamCodecEncryptionException(Throwable cause)
  {
    super(cause);
  }

  public StreamCodecEncryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
  {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
