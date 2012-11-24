/* Quick and dirty MD5-based skey implementation
 *
 * Usage:
 * Get a key at a given sequence:
 * Digest.get("seed", "password") at seq_num
 *
 * Get 4 keys from 10 to 14
 * Digest.get("seed", "password") keys drop 10 take 4 toList
 *
 * Get the next key in a sequence
 * Digest.fromWords("SOP TINA BABE OLGA GORY SO").digest toWords
 * */

import java.nio.ByteBuffer
import sun.security.provider.MD4
import java.security.MessageDigest
import java.util.Arrays

abstract class BadInputException extends Exception
class BadChecksumException extends BadInputException
class BadInputByteException extends BadInputException
class BadInputLengthException extends BadInputException
class BadInputWordException extends BadInputException

object Dictionary {
  val words = io.Source.fromFile("dict.txt").mkString.split(" ")

  def byte(word: String): Int = {
    words.indexOf(word) match {
      case -1 => throw new BadInputWordException
      case n => n
    }
  }

  def word(byte: Int): String = {
    if ((byte & 0x07ff) != byte) {
      throw new BadInputByteException
    }
    words(byte)
  }
}

object Digest {
  def main(args: Array[String]) {
    val cons = Console
    val request: String = cons.readLine("%s: ", "Challenge")
    println()
    val passwd: String = cons.readLine("%s: ", "Password")
    val Seq(num, seed) = if (request contains ' ') {
      request.split(" ").toSeq
    } else {
      Seq("1", request)
    }
    println()
    println(Digest.get(seed, passwd) at Integer.parseInt(num))
  }

  private def fromString(s: String): Digest = {
    new Digest(s.getBytes).digest
  }

  def get(seq: String, key: String): Digest = fromString(seq + key)

  def fromWords(key: String) = {
    val bytes = key split " " map { word: String =>
      Dictionary byte word.toUpperCase
    }
    if (bytes.size != 6) throw new BadInputLengthException
    var l: Long = 0
    for (x <- 0 to 4) {
      l <<= 11
      l |= bytes(x)
    }
    l <<= 9
    l |= bytes(5) >> 2
    val d = new Digest(ByteBuffer.allocate(8).putLong(l).array)
    if (d.checksum != (bytes(5) & 0x3)) {
      throw new BadChecksumException
    }
    d
  }
}

class Digest(a: Array[Byte]) {
  override def equals(that: Any) = {
    that.isInstanceOf[Digest] &&
    Arrays.equals(toArray, that.asInstanceOf[Digest].toArray)
  }
  override def hashCode = Arrays.hashCode(toArray)

  def toArray: Array[Byte] = a

  def toHex: String = a.map { "%02x" format _ } mkString ""

  def checksum: Int = {
    val l = ByteBuffer.wrap(a).getLong
    (for (x <- 0 until 64 by 2) yield {
      ((l >> x) & 0x3).toInt
    }).sum & 0x3
  }

  def toWords: String = {
    val code = ByteBuffer.wrap(a).getLong
    val words = (for (count <- 4 to 0 by -1) yield {
      Dictionary.word(((code >>> (count*11 + 9)) & 0x7ff).toInt)
    }) :+ Dictionary.word((((code << 2) & 0x7fc) | checksum).toInt)
    words mkString " "
  }

  def digest: Digest = {
    val md = MessageDigest.getInstance("MD5")
    md.reset()
    md.update(a)
    val a2 = md.digest
    val a3 = new Array[Byte](8)
    for (count <- 0 until 8) {
      a3(count) = (a2(count) ^ a2(count + 8)).toByte
    }
    new Digest(a3)
  }

  def iterated: Iterator[Digest] = Iterator.iterate(this)(_.digest)
  def keys: Iterator[String] = iterated map { _.toWords }
  def at(count: Int): String = keys drop count next
}
