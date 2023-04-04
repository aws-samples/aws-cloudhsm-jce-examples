/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import java.io.IOException;
import java.security.Key;
import java.security.Security;
import java.security.AuthProvider;
import java.text.MessageFormat;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import com.amazonaws.cloudhsm.jce.jni.exception.AuthenticationException;
import com.amazonaws.cloudhsm.jce.jni.exception.AuthenticationExceptionCause;
import com.amazonaws.cloudhsm.jce.jni.exception.AccountAlreadyLoggedInException;
import com.amazonaws.cloudhsm.jce.jni.exception.FailedLoginException;
import com.amazonaws.cloudhsm.jce.jni.exception.AccountLockedException;

/**
 * This sample demonstrates the different methods of authentication that can be used with the JCE.
 * Please see the official documentation for more information.
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class LoginRunner {
    private static String helpString = "LoginRunner\n" +
            "This sample demonstrates the different methods of authentication that can be used with the JCE.\n" +
            "\n" +
            "Options\n" +
            "\t--method [explicit, system-properties, environment]\n" +
            "\t--user <username>\n" +
            "\t--password <password>\n";

    public static void main(String[] args) throws Exception {
        if (args.length % 2 != 0) {
            help();
            return;
        }

        String method = null;
        String user = null;
        String pass = null;

        for (int i = 0; i < args.length; i+=2) {
            String arg = args[i];
            String value = args[i+1];
            switch (arg) {
                case "--method":
                    method = value;
                    break;
                case "--user":
                    user = value;
                    break;
                case "--password":
                    pass = value;
                    break;
            }
        }

        if (null == method) {
            help();
            return;
        }

        if (method.equals("explicit") || method.equals("system-properties")) {
            if (null == user || null == pass) {
                help();
                return;
            }
        }

        if (method.equals("explicit")) {
            loginWithExplicitCredentials(user, pass);
        } else if (method.equals("system-properties")) {
            loginUsingJavaProperties(user, pass);
        } else if (method.equals("environment")) {
            loginWithEnvVariables();
        }
    }

    public static void help() {
        System.out.println(helpString);
    }

    /**
     * The explicit login method allows users to pass credentials to the Cluster manually. If you obtain credentials
     * from a provider during runtime, this method allows you to login.
     * @param user Name of CU user in HSM.
     * @param pass Password for CU user.
     */
    public static void loginWithExplicitCredentials(String user, String pass) {
        AuthProvider provider;
        try {
            provider = (AuthProvider) Security.getProvider(CloudHsmProvider.PROVIDER_NAME);
            if (provider == null) {
                provider = new CloudHsmProvider();
            }
            Security.addProvider(provider);
        } catch (IOException | ProviderInitializationException | LoginException ex) {
            System.out.println(ex);
            return;
        }
        loginWithPinOnGivenProvider(user, pass, CloudHsmProvider.PROVIDER_NAME);
        logout(provider);
    }

    public static void loginWithPinOnGivenProvider(String user, String password, String providerName) {
        AuthProvider provider = (AuthProvider) Security.getProvider(providerName);
        ApplicationCallBackHandler loginHandler = new ApplicationCallBackHandler(user + ":" + password);
        try {
            provider.login(null, loginHandler);
        } catch(AccountAlreadyLoggedInException e) {
            System.out.printf("\n Account is already logged in \n\n");
        } catch(AccountLockedException e) {
            System.out.printf("\n Account is locked \n\n");
        } catch(FailedLoginException e) {
            System.out.printf("\n Failed to login\n\n");
            e.printStackTrace();
        } catch (LoginException e) {
            e.printStackTrace();
        }
        System.out.printf(MessageFormat.format("\nLogin successful on provider {0} with user {1}!\n\n", providerName, user));
    }

    /**
     * This implicit login method is to set credentials through system properties. This can be done using
     * System.setProperty(), or credentials can be read from a properties file. When implicit credentials are used,
     * you do not have to use the AuthProvider. The login will be done automatically for you.
     * @param user Name of CU user in HSM
     * @param pass Password for CU user.
     */
    public static void loginUsingJavaProperties(String user, String pass) throws Exception {
        System.setProperty("HSM_USER", user);
        System.setProperty("HSM_PASSWORD", pass);

        // When provider is constructed it will use the system properties to automatically
        // log the user in.
        Security.addProvider(new CloudHsmProvider());

        Key aesKey = null;

        try {
            aesKey = SymmetricKeys.generateAESKey(256, "Implicit Java Properties Login Key");
        } catch (AuthenticationException e) {
            AuthenticationExceptionCause cause = e.getCloudHsmExceptionCause();
            if (cause == AuthenticationExceptionCause.UNAUTHENTICATED) {
                System.out.printf("\nProvider is not authenticated\n\n");
            }
            e.printStackTrace();
        }
        assert(aesKey != null);
        System.out.printf("\nLogin successful!\n\n");
    }

    /**
     * This implicit login method uses environment variables to login. To use this method, you must set the following
     * environment variables before running the test:
     * HSM_USER
     * HSM_PASSWORD
     *
     * AuthProvider is not required to use implicit credentials. When you try to perform operations, the login
     * will be done automatically.
     */
    public static void loginWithEnvVariables() throws Exception {

        // When provider is constructed it will use the environment variables to automatically
        // log the user in.
        Security.addProvider(new CloudHsmProvider());

        Key aesKey = null;

        try {
            aesKey = SymmetricKeys.generateAESKey(256, "Implicit Java Properties Login Key");
        } catch (AuthenticationException e) {
            AuthenticationExceptionCause cause = e.getCloudHsmExceptionCause();
            if (cause == AuthenticationExceptionCause.UNAUTHENTICATED) {
                System.out.printf("\nProvider is not authenticated\n\n");
            }
            e.printStackTrace();
        }

        System.out.printf("\nLogin successful!\n\n");
    }

    /**
     * Logout will force the provider to end your session.
     */
    public static void logout(AuthProvider provider) {
        // Explicit logout is only available when you explicitly login using
        // AuthProvider's Login method
        try {
            provider.logout();
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.printf(MessageFormat.format("\nLogout successful on provider {0}!\n\n", provider.getName()));
    }

    static class ApplicationCallBackHandler implements CallbackHandler {

        private String cloudhsmPin = null;

        public ApplicationCallBackHandler(String pin) {
            cloudhsmPin = pin;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback)callbacks[i];
                    pc.setPassword(cloudhsmPin.toCharArray());
                }
            }
        }
    }
}