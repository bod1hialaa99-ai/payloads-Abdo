import com.ibm.as400.access.*;

public class TestIBMi {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java -cp jt400.jar:. TestIBMi <host> <username> [password]");
            System.exit(1);
        }
        
        String host = args[0];
        String username = args[1];
        String password = args.length > 2 ? args[2] : "";
        
        System.out.println("Testing: " + username + " @ " + host);
        
        try {
            AS400 system = new AS400(host, username, password);
            system.connectService(AS400.COMMAND);
            
            System.out.println("[+] SUCCESS! Connected as: " + system.getUserId());
            
            // Get OS version
            try {
                SystemValue sv = new SystemValue(system, "QOSVRM");
                System.out.println("[+] OS Version: " + sv.getValue());
n            } catch (Exception e) {}
            
            system.disconnectAllServices();
            
        } catch (AS400SecurityException e) {
            System.out.println("[-] Auth failed: " + e.getMessage());
            System.out.println("[-] Return code: " + e.getReturnCode());
        } catch (Exception e) {
            System.out.println("[-] Error: " + e.getMessage());
        }
    }
}
