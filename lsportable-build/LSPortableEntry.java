import java.security.Security;
import org.lsposed.patch.LSPatch;

public final class LSPortableEntry {

	private LSPortableEntry() {}

	public static void main(String[] args) {
		// ART ignores -Djava.security.properties, so the keystore type is set here
		Security.setProperty("keystore.type", "PKCS12");
		try {
			LSPatch.main(args);
		} catch (Throwable t) {
			t.printStackTrace();
			System.exit(1);
		}
	}
}
