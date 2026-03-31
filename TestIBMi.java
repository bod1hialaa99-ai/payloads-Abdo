import com.ibm.as400.access.*;

public class TestIBMi {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java -cp jt400.jar:. TestIBMi <host> <username> [password]");
            System.out.println("Examples:");
            System.out.println("  java -cp jt400.jar:. TestIBMi 10.224.56.66 QSECOFR QSECOFR");
            System.out.println("  java -cp jt400.jar:. TestIBMi 10.224.56.66 QSECOFR \"\"  (test blank password)");
            System.exit(1);
        }
        
        String host = args[0];
        String username = args[1];
        String password = args.length > 2 ? args[2] : "";
        
        System.out.println("========================================");
        System.out.println("IBM i Connection Test");
        System.out.println("Target: " + host);
        System.out.println("User: " + username);
        System.out.println("Password: " + (password.isEmpty() ? "[EMPTY - TESTING UNAUTHENTICATED]" : "[PROVIDED]"));
        System.out.println("========================================\n");
        
        try {
            System.out.println("[*] Creating AS400 object...");
            AS400 system = new AS400(host, username, password);
            
            System.out.println("[*] Attempting to connect to COMMAND service...");
            system.connectService(AS400.COMMAND);
            
            System.out.println("\n[+] SUCCESS! Connected to IBM i!");
            System.out.println("[+] System Name: " + system.getSystemName());
            System.out.println("[+] User ID: " + system.getUserId());
            
            // Try to get system version
            try {
                SystemValue sv = new SystemValue(system, "QOSVRM");
                System.out.println("[+] OS Version: " + sv.getValue());
            } catch (Exception e) {
                System.out.println("[!] Could not retrieve OS version");
            }
            
            // Try to get security level
            try {
                SystemValue sv = new SystemValue(system, "QSECURITY");
                System.out.println("[+] Security Level (QSECURITY): " + sv.getValue());
            } catch (Exception e) {
                System.out.println("[!] Could not retrieve security level");
            }
            
            // Check if we can run commands
            try {
                CommandCall cmd = new CommandCall(system);
                System.out.println("\n[*] Testing command execution...");
                if (cmd.run("RTVJOBA USER(&USER)")) {
                    System.out.println("[+] Command execution successful!");
                }
            } catch (Exception e) {
                System.out.println("[!] Command execution test failed: " + e.getMessage());
            }
            
            system.disconnectAllServices();
            System.out.println("\n[+] Connection closed successfully");
            
        } catch (AS400SecurityException e) {
            System.out.println("\n[-] AUTHENTICATION FAILED!");
            System.out.println("[-] Message: " + e.getMessage());
            System.out.println("[-] Return Code: " + e.getReturnCode());
            
            // Decode return code using correct constant names
            int rc = e.getReturnCode();
            if (rc == AS400SecurityException.PASSWORD_INCORRECT) {
                System.out.println("[*] Reason: Password is incorrect");
            } else if (rc == AS400SecurityException.PASSWORD_NOT_SET) {
                System.out.println("[*] Reason: Password not set for user");
            } else if (rc == AS400SecurityException.USERID_NOT_SET) {
                System.out.println("[*] Reason: User ID not set");
            } else if (rc == AS400SecurityException.USERID_UNKNOWN) {
                System.out.println("[*] Reason: User ID is not valid/unknown");
            } else if (rc == AS400SecurityException.USERID_DISABLE) {
                System.out.println("[*] Reason: User ID is disabled");
            } else if (rc == AS400SecurityException.PASSWORD_EXPIRED) {
                System.out.println("[*] Reason: Password has expired");
            } else {
                System.out.println("[*] Reason: Unknown (return code: " + rc + ")");
            }
            
        } catch (Exception e) {
            System.out.println("\n[-] CONNECTION FAILED!");
            System.out.println("[-] Exception: " + e.getClass().getName());
            System.out.println("[-] Message: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
