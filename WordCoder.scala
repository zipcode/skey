import sun.security.provider.MD4

object Dictionary {
  val words = io.Source.fromFile("dict.txt").mkString.split(" ")

  def byte(word: String): Int = {
    words.indexOf(word) match {
      case -1 => throw new RuntimeException("Bad word")
      case n => n
    }
  }

  def word(byte: Int): String = {
    if ((byte & 0xf800) != 0) {
      throw new RuntimeException("Bad byte")
    }
    words(byte)
  }
}

object Digest {
  def encode(a: Array[Byte]): String = {
    val code = java.nio.ByteBuffer.wrap(a).getLong
    (for (count <- 5 to 0 by -1) yield {
      Dictionary.word(((code >> (count*11)) & 0x7ff).toInt)
    }) mkString " "
  }

  def decode(code: String): Array[Byte] = {
    val chunks = code.split(" ") map { x: String => Dictionary.byte(x) }
    var output: Long = 0
    for (chunk <- chunks) {
      output <<= 11
      output |= chunk
    }
    java.nio.ByteBuffer.allocate(16).putLong(output).array
  }
}

case class Digest(mdi: () => MessageDigest) {
  def stringToArray(in: String): Array[Byte] = {
    val os = new java.io.ByteArrayOutputStream
    val osw = new java.io.OutputStreamWriter(os)
    osw.write(in)
    osw.close
    os.toByteArray
  }

  def digestround(in: Array[Byte]): Array[Byte] = {
    val md = mdi()
    md.update(in)
    val d = md.digest()
    (0 until 8) map { x: Int =>
      (d(x) ^ d(x + 8)) toByte
    } toArray
  }

  def arrayToLong(a: Array[Byte]): Long = {
    java.nio.ByteBuffer.wrap(a).getLong
  }

  def longToArray(l: Long): Array[Byte] = {
    java.nio.ByteBuffer.allocate(16).putLong(l).array
  }

  def step(s: String): String = {
    ""
  }
}
