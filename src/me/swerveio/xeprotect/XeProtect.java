package me.swerveio.xeprotect;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;

public class XeProtect {
	
	private static int ByteToInt(byte[] buffer) {
		if (buffer.length < 4) {
			byte[] buffer2 = new byte[8];
			System.arraycopy(buffer, 0, buffer2, 4 - buffer.length, buffer.length);
			buffer = buffer2;
		}
		return ByteBuffer.wrap(buffer).position(0).getInt();
	}
	
	private static int ReverseInt(int i) {
        return (i & 0xFF) << 0x18 | (i & 0xFF00) << 0x08 | (i & 0xFF0000) >> 0x08 | ( i >> 0x18) & 0xFF;
    }
	
	private static ByteBuffer getSectionInfo(byte[] decryptedXexBuffer, String section) {
		try {
			int addr = KMPMatch.indexOf(decryptedXexBuffer, section.getBytes());
			
			String sectionName = new String(Arrays.copyOfRange(decryptedXexBuffer, addr, addr + 0x8));
			if (addr != -1 && sectionName.contains(section)) {
				return ByteBuffer.wrap(Arrays.copyOfRange(decryptedXexBuffer, addr + 8, addr + 16));
			}
		} catch (Exception ex) {}		
		return null;
	}
	
	private static byte[] getSectionData(byte[] decryptedXexBuffer, String section) {
		try {
			ByteBuffer buffer = getSectionInfo(decryptedXexBuffer, section);
			if (buffer != null) {
				int Address = ReverseInt(buffer.getInt(4)) + 0x1000;
				int Length = ReverseInt(buffer.getInt(0));
				return Arrays.copyOfRange(decryptedXexBuffer, Address, Address + Length);
			}
		} catch (Exception ex) { }
		return null;
	}
	
	public static void main(String[] args) {
		File xexFile = new File(args[0]);
		File parentFile = new File(XeProtect.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getAbsoluteFile().getParentFile();
		
		if (xexFile.exists()) {
			try {
				File xexDecryptedFile = File.createTempFile("temp", null);
				
				Process process = Runtime.getRuntime().exec(String.format("\"%s\\xextool.exe\" -e u -c u -o \"%s\" \"%s\"", parentFile, xexDecryptedFile.getAbsolutePath(), xexFile.getAbsolutePath()));
				process.waitFor();
				
				byte[] xexDecryptedBuffer = FileUtils.readFileToByteArray(xexDecryptedFile);
				byte[] sectionData = getSectionData(xexDecryptedBuffer, ".text");
				
				if (sectionData != null)  {
					ByteBuffer text_sectionInfo = getSectionInfo(xexDecryptedBuffer, ".text");
					
					int base_address = ByteToInt(Arrays.copyOfRange(xexDecryptedBuffer, 0x34, 0x34 + 4));
				
					if (text_sectionInfo != null) {
						int Address_text = ReverseInt(text_sectionInfo.getInt(4)) + 0x1000;
						int Length_text = ReverseInt(text_sectionInfo.getInt(0)) - 0x1000;
						
						ByteBuffer buffer = ByteBuffer.wrap(xexDecryptedBuffer);
						buffer.position(Address_text);
						buffer.get(sectionData);
						
						for (int i = 0; i < Length_text; i++) {
							sectionData[i] ^= 26;
						}
						
						buffer.position(Address_text);
						buffer.put(sectionData);
						
						Address_text = base_address + Address_text - 0x1000;
						
						//buffer.position(KMPMatch.indexOf(xexDecryptedBuffer, "XeOb".getBytes()));
						
						FileUtils.writeByteArrayToFile(xexDecryptedFile, buffer.array());
					}
				}
				
				process = Runtime.getRuntime().exec(String.format("\"%s\\xextool.exe\" -e e -c c -o \"%s\" \"%s\"", parentFile, xexFile.getAbsolutePath(), xexDecryptedFile.getAbsolutePath()));
				process.waitFor();
				
				xexDecryptedFile.deleteOnExit();
			} catch (IOException | InterruptedException ex) {}
		}
	}

}
