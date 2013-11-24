package com.hencjo.summer.security.ldap.asn;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import sun.security.util.BigInt;
import com.hencjo.summer.security.ldap.DerDecodeException;
import com.hencjo.summer.security.ldap.utils.Charsets;
import com.hencjo.summer.security.ldap.utils.Hex;

public class ASN {
	public static interface AsnNode {
		public byte[] der();
		public int decode(InputStream inputStream) throws IOException, DerDecodeException;
	}
	
	public static final class AsnSequence implements AsnNode {
		private final AsnNode[] ans;

		public AsnSequence(AsnNode[] ans) {
			this.ans = ans;
		}

		@Override
		public byte[] der() {
			int accumulatedLength = 0;
			List<byte[]> childbytes = new ArrayList<>();
			for (AsnNode an : ans) {
				byte[] der = an.der();
				childbytes.add(der);
				accumulatedLength += der.length;
			}
			
			ByteBuffer byteBuffer = ByteBuffer.allocate(accumulatedLength + 2);
			byteBuffer.put((byte)0x30);
			byteBuffer.put((byte) accumulatedLength);
			for (byte[] bs : childbytes) {
				byteBuffer.put(bs);
			}
			return byteBuffer.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			int read = inputStream.read();
			if (read != 0x30) throw new DerDecodeException("Expected first byte to be 0x30. It was: " + prettyHexByte(read));
			
			ReadLength rl = readLength(inputStream);
			if (rl.length == 0) return (rl.readBytes + 1);
			
			int consumedBytes = processChildren(ans, inputStream);
			if (rl.length != consumedBytes) throw new DerDecodeException("Length mismatch. Expected subsection to contain " + rl.length + " bytes but consumed " + consumedBytes + " bytes.");
			
			return (1 + rl.readBytes + consumedBytes);
		}
	}

	public static final class AsnApplication implements AsnNode {
		private final int application;
		private final AsnNode[] ans;

		public AsnApplication(int application, AsnNode[] ans) {
			this.application = application;
			this.ans = ans;
		}

		@Override
		public byte[] der() {
			int safeApplication = application & 0x1F;
			byte type = (byte) (0x60 | safeApplication);

			int accumulatedLength = 0;
			List<byte[]> childbytes = new ArrayList<>();
			for (AsnNode an : ans) {
				byte[] der = an.der();
				childbytes.add(der);
				accumulatedLength += der.length;
			}
			
			ByteBuffer byteBuffer = ByteBuffer.allocate(accumulatedLength + 2);
			byteBuffer.put(type);
			byteBuffer.put((byte) accumulatedLength);
			for (byte[] bs : childbytes) {
				byteBuffer.put(bs);
			}
			return byteBuffer.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			int type = inputStream.read();
			int expectedType = 0x60 | (application & 0x3F);
			if (type != expectedType) throw new DerDecodeException("Expected first byte to be " + prettyHexByte(expectedType) + ". It was: " + prettyHexByte(type));
			
			ReadLength rl = readLength(inputStream);
			if (rl.length == 0) return (rl.readBytes + 1);
			
			int consumedBytes = processChildren(ans, inputStream);
			if (rl.length != consumedBytes) throw new DerDecodeException("Length mismatch. Expected subsection to contain " + rl.length + " bytes but consumed " + consumedBytes + " bytes.");
			
			return (1 + rl.readBytes + consumedBytes);
		}
	}

	public static final class AsnString implements AsnNode {
		private String value = "";
		
		public void set(String value) { this.value = value; }
		
		@Override
		public byte[] der() {
			byte[] bytes = value.getBytes(Charset.forName("UTF-8"));
			ByteBuffer byteBuffer = ByteBuffer.allocate(bytes.length + 2);
			byteBuffer.put((byte) 0x04);
			byteBuffer.put((byte) bytes.length);
			byteBuffer.put(bytes);
			return byteBuffer.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			int type = inputStream.read();
			if (type != 0x04) throw new DerDecodeException("Expected first byte to be 0x04. It was: " + prettyHexByte(type));
			
			ReadLength rl = readLength(inputStream);
			if (rl.length == 0) {
				value = "";
				return (rl.readBytes + 1);
			}
			
			byte[] bs = new byte[rl.length];
			for (int i = 0; i < rl.length; i++) {
				int read = inputStream.read();
				if (read == -1) throw new IOException("Unexpected end of input.");
				bs[i] = (byte) read;
			}
			value = new String(bs, Charsets.UTF8);
			return (1 + rl.readBytes + rl.length);
		}

		public String get() {
			return value;
		}
	}

	public static final class AsnRaw implements AsnNode {
		private byte[] value;
		
		public void set(byte[] value) { this.value = value; }
		
		@Override
		public byte[] der() {
			return value;
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			// TODO Auto-generated method stub
			return 0;
		}
	}

	public static final class AsnInteger implements AsnNode {
		private int value;
		
		public void set(int value) { this.value = value; }
		
		@Override
		public byte[] der() {
			return ByteBuffer.allocate(6)
					.put((byte)0x02)
					.put((byte)0x04)
					.putInt(value)
					.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			int type = inputStream.read();
			if (type != 0x02) throw new DerDecodeException("Expected first byte to be 0x02. It was: " + prettyHexByte(type));
			
			ReadLength rl = readLength(inputStream);
			if (rl.length == 0) return (rl.readBytes + 1);
			
			byte[] bs = new byte[rl.length];
			for (int i = 0; i < rl.length; i++) {
				int read = inputStream.read();
				if (read == -1) throw new IOException("Unexpected end of input.");
				bs[i] = (byte) read;
			}
			value = new BigInt(bs).toInt();
			return (1 + rl.readBytes + rl.length);
		}

		public int get() {
			return value;
		}
	}
	
	public static final class AsnEnumerated implements AsnNode {
		private int value;
		
		public void set(int value) { this.value = value; }
		
		@Override
		public byte[] der() {
			return ByteBuffer.allocate(6)
					.put((byte)0x02)
					.put((byte)0x04)
					.putInt(value)
					.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			int type = inputStream.read();
			if (type != 0x0a) throw new DerDecodeException("Expected first byte to be 0x0a. It was: " + prettyHexByte(type));
			
			ReadLength rl = readLength(inputStream);
			if (rl.length == 0) return (rl.readBytes + 1);
			
			byte[] bs = new byte[rl.length];
			for (int i = 0; i < rl.length; i++) {
				int read = inputStream.read();
				if (read == -1) throw new IOException("Unexpected end of input.");
				bs[i] = (byte) read;
			}
			value = new BigInt(bs).toInt();
			return (1 + rl.readBytes + rl.length);
		}

		public int get() {
			return value;
		}
	}
	
	public static final class AsnChoice implements AsnNode {
		private final int choice;
		private final AsnNode an;

		public AsnChoice(int choice, AsnNode an) {
			this.choice = choice;
			this.an = an;
		}

		@Override
		public byte[] der() {
			byte safeApplication = (byte) (choice & 0x1F);
			byte type = (byte) (0x80 | safeApplication);
			
			byte[] der = an.der();
			ByteBuffer byteBuffer = ByteBuffer.allocate(der.length + 2);
			byteBuffer.put(type);
			byteBuffer.put((byte) der.length);
			byteBuffer.put(der);
			return byteBuffer.array();
		}

		@Override
		public int decode(InputStream inputStream) throws IOException, DerDecodeException {
			// TODO Auto-generated method stub
			return 0;
		}
	}
	
	public static AsnString string() {
		return new AsnString();
	}

	public static AsnString nullValue() {
		return new AsnString();
	}

	public static int processChildren(AsnNode[] ans, InputStream inputStream) throws IOException, DerDecodeException {
		int readBytes = 0;
		for (AsnNode an : ans) {
			readBytes += an.decode(inputStream);
		}
		return readBytes;
	}

	public static String prettyHexByte(int read) {
		return Hex.prettyByte((byte) read);
	}

	public static final class ReadLength {
		public final int length;
		public final int readBytes;

		public ReadLength(int length, int readBytes) {
			this.length = length;
			this.readBytes = readBytes;
		}
	}
	
	public static ReadLength readLength(InputStream inputStream) throws IOException {
		int naiveLength = inputStream.read();
		if (naiveLength == -1) throw new IOException("Unexpected end of input.");
		
		int last7bytes = (naiveLength & 0x7f);
		if ((naiveLength & 0x80) != 0x80) {
			return new ReadLength((last7bytes), 1);
		}
		
		int bytesContainingLength = last7bytes;
		byte[] bs = new byte[bytesContainingLength];
		for (int i = 0; i < bytesContainingLength; i++) {
			int read = inputStream.read();
			if (read == -1) throw new IOException("Unexpected end of input.");
			bs[i] = (byte) read;
		}
		return new ReadLength(new BigInt(bs).toInt(), bytesContainingLength + 1);
	}

	public static AsnRaw raw() {
		return new AsnRaw();
	}

	public static AsnInteger integer() {
		return new AsnInteger();
	}

	public static AsnEnumerated enumerated() {
		return new AsnEnumerated();
	}

	public static AsnSequence sequence(AsnNode ... ans) {
		return new AsnSequence(ans);
	}
	
	public static AsnChoice choice(int choice, AsnNode an) {
		return new AsnChoice(choice, an);
	}
	
	public static AsnApplication application(int application, AsnNode ... ans) {
		return new AsnApplication(application, ans);
	}
}
