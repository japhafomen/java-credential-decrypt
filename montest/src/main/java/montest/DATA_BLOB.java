package montest;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.DWORD;

public class DATA_BLOB extends com.sun.jna.Structure {

	 public DWORD cbData;
     public Pointer pbData;

     public DATA_BLOB() {}

     public DATA_BLOB(byte[] data) {
         this.cbData = new DWORD(data.length);
         this.pbData = new Memory(data.length);
         this.pbData.write(0, data, 0, data.length);
     }

     public byte[] getData() {
         return pbData.getByteArray(0, cbData.intValue());
     }

     @Override
     protected java.util.List<String> getFieldOrder() {
         return java.util.Arrays.asList("cbData", "pbData");
     }
}
