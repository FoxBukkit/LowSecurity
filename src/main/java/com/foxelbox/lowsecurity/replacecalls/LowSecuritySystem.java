package com.foxelbox.lowsecurity.replacecalls;

public class LowSecuritySystem {
    private static SecurityManager _securityManager = null;

    public static void setSecurityManager(SecurityManager securityManager) {
        _securityManager = securityManager;
    }

    public static SecurityManager getSecurityManager() {
        return _securityManager;
    }
}
