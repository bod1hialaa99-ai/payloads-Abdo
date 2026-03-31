import com.ibm.as400.access.*;

public class TestIBMi {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java -cp jt400.jar:. TestIBMi <host> <username> [password]");
            System.exit(1);
        }
        
        String host = args[0];
        String username = args[1];
        String password = args.length > 2 ? args[2] : "";  // Empty password for testing
        
        try {
            System.out.println("[*] Connecting to " + host + " as " + username + "...");
            
            // Create AS400 object
            AS400 system = new AS400(host, username, password);
            
            // Test connection (this will attempt authentication)
            system.connectService(AS400.COMMAND);
            
            System.out.println("[+] SUCCESS! Connected to IBM i");
            System.out.println("[+] System: " + system.getSystemName());
            System.out.println("[+] User: " + system.getUserId());
            
            // Get system info
            try {
                SystemValue sv = new SystemValue(system, "QOSVRM");
                System.out.println("[+] OS Version: " + sv.getValue());
            } catch (Exception e) {
                System.out.println("[!] Could not get OS version");
            }
            
            system.disconnectAllServices();
            
        } catch (AS400SecurityException e) {
            System.out.println("[-] AUTHENTICATION FAILED: " + e.getMessage());
            System.out.println("[*] Return code: " + e.getReturnCode());
            // Return codes:
            // 0x0001 = Password not correct
            // 0x0002 = User ID not correct
            // 0x0003 = Password expired
            // 0x0004 = User ID disabled
        } catch (Exception e) {
            System.out.println("[-] CONNECTION FAILED: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
