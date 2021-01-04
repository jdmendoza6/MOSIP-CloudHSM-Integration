/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.ImportKey;
import com.cavium.cfm2.LoginManager;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumECPrivateKey;
import com.cavium.key.CaviumECPublicKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;
import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.exception.NoSuchSecurityProviderException;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.keygenerator.bouncycastle.constant.KeyGeneratorExceptionConstant;
// import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerErrorCode;
import io.mosip.kernel.keymanager.hsm.util.CertificateUtility;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * This sample demonstrates the different methods of authentication that can be used with the JCE.
 * Please see the official documentation for more information.
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class KeyStoreImpl {

  private static String signAlgorithm = "SHA256withRSA";
  private static int asymmetricKeyLength = 2048;
  private static String symmetricKeyAlgorithm = "AES";
  private static String asymmetricKeyAlgorithm = "RSA";
  private static String keystorePass = "test";
  private static int symmetricKeyLength = 256;
  private static KeyStore keyStore;
  private static Provider provider;
  private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";
  private static String keystoreType = "PKCS11";
  private static final int NO_OF_RETRIES = 3;
  private static String commonName = "commonName";
  private static String organizationalUnit = "organizationalUnit";
  private static String organization = "organization";
  private static String location = "location";
  private static String state = "state";
  private static String country = "country";
  private static LocalDateTime notBefore = LocalDateTime.now();
  private static LocalDateTime notAfter = LocalDateTime.now().plusDays(100);
  private static String keystoreFile = "test.keystore";
  private static String helpString =
    "LoginRunner\n" +
    "This sample demonstrates the different methods of authentication that can be used with the JCE.\n" +
    "\n" +
    "Options\n" +
    "\t--user <username>\n" +
    "\t--password <password>\n" +
    "\t--partition <partition>\n\n";

  public static void main(String[] args) throws Exception {
    String user = null;
    String pass = null;
    String partition = null;

    for (int i = 0; i < args.length; i += 2) {
      String arg = args[i];
      switch (arg) {
        case "--user":
          user = args[i + 1];
          break;
        case "--password":
          pass = args[i + 1];
          break;
        case "--partition":
          partition = args[i + 1];
          break;
        case "--help":
          System.out.println(helpString);
          return;
      }
    }
    try {
      afterPropertiesSet();
      loginUsingJavaProperties(user, pass, partition);
      // instantiate keystore

    } catch (Exception e) {
      System.out.println(e);
      return;
    }

    //this shows that we have successfully connected to the keystore
    System.out.printf("The KeyStore contains %d keys\n", keyStore.size());

    //list all key aliases
    List<String> keyAliases = new ArrayList<String>();
    String lastKey = "";
    keyAliases = getAllAlias();
    System.out.println("Method 'getAllAlias'");
    for (String keyAlias : keyAliases) {
      System.out.println("Key Alias: " + keyAlias);
      lastKey = keyAlias;
    }

    //getKeystoreProviderName
    System.out.println("Method 'getKeystoreProviderName'");
    System.out.println(getKeystoreProviderName());

    //generateSymmetricKey
    System.out.println("Method 'generateSymmetricKey'");
    String symmetricKeyAlgorithm = "AES";
    String keyalias = "AES symmetric key " + UUID.randomUUID();
    System.out.println("Alias " + keyalias);
    SecretKey aessymmetrickey = generateSymmetricKey(keyalias);
    System.out.println("Generated aes symmetric key: " + aessymmetrickey);

    //storeSymmetricKey
    System.out.println("Method 'storeSymmetricKey': " + keyalias);
    storeSymmetricKey(aessymmetrickey, keyalias);

    displayAllKeys();

    //generateKeyPair()
    System.out.println("Method 'generateKeyPair': ");
    String rsaKeyAlias = "RSA " + UUID.randomUUID();
    KeyPair keypair = generateKeyPair(rsaKeyAlias + ":public", rsaKeyAlias);
    System.out.println("generated keypair: " + keypair);

    // generateCertificate
    System.out.println("Method 'generateCertificate': from keypair " + keypair);
    CertificateParameters certParams = new CertificateParameters(
      commonName,
      organizationalUnit,
      organization,
      location,
      state,
      country,
      notBefore,
      notAfter
    );
    X500Principal signerPrincipal = new X500Principal(
      "CN=" +
      commonName +
      ", OU=" +
      organizationalUnit +
      ", O=" +
      organization +
      ", L=" +
      location +
      ", S=" +
      state +
      ", C=" +
      country
    );
    Certificate certificate = generateCertificate(
      keypair.getPrivate(),
      keypair.getPublic(),
      certParams,
      signerPrincipal
    );
    System.out.println("generated certificate: " + certificate);

    // storeCertificate private
    Certificate[] chain = new Certificate[] { certificate };
    System.out.println("Method private 'storeCertificate': " + rsaKeyAlias);
    storeCertificate(rsaKeyAlias, chain, keypair.getPrivate());

    //storeAsymmetricKey
    System.out.println("Method 'storeAsymmetricKey': " + rsaKeyAlias);
    storeAsymmetricKey(keypair, rsaKeyAlias, notBefore, notAfter);
    displayAllKeys();

    //generateAndStoreSymmetricKey
    String symmetricKeyAlias = "Generated AES " + UUID.randomUUID();
    System.out.println(
      "Method 'generateAndStoreSymmetricKey': " + symmetricKeyAlias
    );
    generateAndStoreSymmetricKey(symmetricKeyAlias);
    displayAllKeys();

    //getAsymmetricKey
    System.out.println("Method 'getAsymmetricKey': " + rsaKeyAlias);
    PrivateKeyEntry asymmetrickKey = getAsymmetricKey(rsaKeyAlias);
    System.out.println("retrieved 'AsymmetricKey': " + asymmetrickKey);

    //generateAndStoreAsymmetricKey
    String asymmetricKeyAlias = "Generate and Store RSA " + UUID.randomUUID();
    System.out.println(
      "Method 'generateAndStoreAsymmetricKey': " + rsaKeyAlias
    );
    generateAndStoreAsymmetricKey(asymmetricKeyAlias, rsaKeyAlias, certParams);
    displayAllKeys();

    //getCertificate
    System.out.println("Method 'getCertificate': " + rsaKeyAlias);
    X509Certificate X509Cert = getCertificate(rsaKeyAlias);
    System.out.println("retrieved X509Certificate: " + X509Cert);

    //getPrivateKey
    System.out.println("Method 'getPrivateKey': " + rsaKeyAlias);
    PrivateKey privateKey = getPrivateKey(rsaKeyAlias);
    System.out.println("retrieved privateKey: " + privateKey);

    //getPublicKey
    System.out.println("Method 'getPublicKey': " + rsaKeyAlias);
    PublicKey publicKey = getPublicKey(rsaKeyAlias);
    System.out.println("retrieved publicKey: " + publicKey);

    //getSymmetricKey
    System.out.println("Method 'getSymmetricKey': " + keyalias);
    SecretKey secretKey = getSymmetricKey(keyalias);
    System.out.println("retrieved secretKey: " + secretKey);

    System.out.println("Method 'getAsymmetricKey': " + rsaKeyAlias);
    System.out.println(
      "retrieved 'AsymmetricKey': " + getAsymmetricKey(rsaKeyAlias)
    );


    displayAllKeys();

    logout();
    System.out.println("Successfully Logged out!");
  }

  // public static void help() {
  //   System.out.println(helpString);
  // }

  /**
   * The explicit login method allows users to pass credentials to the Cluster manually. If you obtain credentials
   * from a provider during runtime, this method allows you to login.
   * @param user Name of CU user in HSM
   * @param pass Password for CU user.
   * @param partition HSM ID
   */

  public static void deleteAllKeys() throws Exception {
    List<String> keyAliases = new ArrayList<String>();
    keyAliases = getAllAlias();
    System.out.printf("The KeyStore contains %d keys\n", keyStore.size());
    System.out.println("Remaining keys");

    for (String keyAlias : keyAliases) {
      deleteKey(keyAlias);
      // displayAllKeys();
    }
  }

  public static void loginWithExplicitCredentials(
    String user,
    String pass,
    String partition
  ) {
    LoginManager lm = LoginManager.getInstance();
    try {
      lm.login(partition, user, pass);
      System.out.printf("\nLogin successful!\n\n");
    } catch (CFM2Exception e) {
      if (CFM2Exception.isAuthenticationFailure(e)) {
        System.out.printf("\nDetected invalid credentials\n\n");
      }

      e.printStackTrace();
    }
  }

  /**
   * One implicit login method is to set credentials through system properties. This can be done using
   * System.setProperty(), or credentials can be read from a properties file. When implicit credentials are used,
   * you do not have to use the LoginManager. The login will be done automatically for you.
   * @param user Name of CU user in HSM
   * @param pass Password for CU user.
   * @param partition HSM ID
   */
  public static void loginUsingJavaProperties(
    String user,
    String pass,
    String partition
  )
    throws Exception {
    System.setProperty("HSM_PARTITION", partition);
    System.setProperty("HSM_USER", user);
    System.setProperty("HSM_PASSWORD", pass);

    Key aesKey = null;

    try {
      aesKey =
        SymmetricKeys.generateAESKey(256, "Implicit Java Properties Login Key");
    } catch (Exception e) {
      if (CFM2Exception.isAuthenticationFailure(e)) {
        System.out.printf("\nDetected invalid credentials\n\n");
        e.printStackTrace();
        return;
      }

      throw e;
    }

    assert (aesKey != null);
    System.out.printf("\nLogin successful!\n\n");
  }

  /**
   * One implicit login method is to use environment variables. To use this method, you must set the following
   * environment variables before running the test:
   * HSM_USER
   * HSM_PASSWORD
   * HSM_PARTITION
   *
   * The LoginManager is not required to use implicit credentials. When you try to perform operations, the login
   * will be done automatically.
   */
  public static void loginWithEnvVariables() throws Exception {
    Key aesKey = null;

    try {
      aesKey =
        SymmetricKeys.generateAESKey(256, "Implicit Java Properties Login Key");
    } catch (Exception e) {
      if (CFM2Exception.isAuthenticationFailure(e)) {
        System.out.printf("\nDetected invalid credentials\n\n");
        e.printStackTrace();
        return;
      }

      throw e;
    }

    System.out.printf("\nLogin successful!\n\n");
  }

  /**
   * Logout will force the LoginManager to end your session.
   */
  public static void logout() {
    try {
      LoginManager.getInstance().logout();
    } catch (CFM2Exception e) {
      e.printStackTrace();
    }
  }

  public static void afterPropertiesSet() throws Exception {
    // if (!isConfigFileValid()) {
    //   LOGGER.info(
    //     "sessionId",
    //     "KeyStoreImpl",
    //     "Creation",
    //     "Config File path is not valid or contents invalid entries. " +
    //     "So, Loading keystore as offline encryption."
    //   );
    //   BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    //   Security.addProvider(bouncyCastleProvider);
    //   this.keyStore =
    //     getKeystoreInstance(KEYSTORE_TYPE_PKCS12, bouncyCastleProvider);
    //   loadKeystore();
    //   return;
    // }
    provider = setupProvider();
    Security.removeProvider(provider.getName());
    addProvider(provider);
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(bouncyCastleProvider);
    // this.keyStore = getKeystoreInstance(keystoreType, provider);
    keyStore = KeyStore.getInstance("CloudHSM");
    loadKeystore();
    // loadCertificate();
  }

  private static void reloadProvider() throws Exception {
    // LOGGER.info(
    //   "sessionId",
    //   "KeyStoreImpl",
    //   "KeyStoreImpl",
    //   "reloading provider"
    // );
    if (Objects.nonNull(provider)) {
      Security.removeProvider(provider.getName());
    }
    Provider provider = setupProvider();
    addProvider(provider);
    // this.keyStore = getKeystoreInstance(keystoreType, provider);
    keyStore = KeyStore.getInstance("CloudHSM");
    loadKeystore();
    keyStore.load(null, null);
  }

  private static void loadKeystore() throws Exception {
    try {
      FileInputStream instream = new FileInputStream(keystoreFile);
      switch (keystoreType) {
        case "PKCS11":
          // keyStore.load(null, null);
          keyStore.load(instream, keystorePass.toCharArray());
          break;
        case "BouncyCastleProvider":
          // added try with res for sonar bug fix
          try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keyStore.load(fis, keystorePass.toCharArray());
          }
          break;
        default:
          // keyStore.load(null, null);
          keyStore.load(instream, keystorePass.toCharArray());
          break;
      }
    } catch (FileNotFoundException ex) {
      keyStore.load(null, null);
    } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
  }

  private static KeyStore getKeystoreInstance(
    String keystoreType,
    Provider provider
  ) {
    KeyStore mosipKeyStore = null;
    try {
      mosipKeyStore = KeyStore.getInstance(keystoreType, provider);
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
    return mosipKeyStore;
  }

  private static void addProvider(Provider provider) {
    if (-1 == Security.addProvider(provider)) {
      throw new NoSuchSecurityProviderException(
        KeymanagerErrorCode.NO_SUCH_SECURITY_PROVIDER.getErrorCode(),
        KeymanagerErrorCode.NO_SUCH_SECURITY_PROVIDER.getErrorMessage()
      );
    }
  }

  public static List<String> getAllAlias() {
    // Enumeration<String> enumeration = null;
    // try {
    //   enumeration = keyStore.aliases();
    // } catch (KeyStoreException e) {
    //   throw new KeystoreProcessingException(
    //     KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
    //     KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
    //     e.getMessage(),
    //     e
    //   );
    // }
    // return Collections.list(enumeration);
    List<String> aliasList = new ArrayList<String>();
    try {
      for (
        Enumeration<String> entry = keyStore.aliases();
        entry.hasMoreElements();
      ) {
        String label = entry.nextElement();
        // System.out.println(label);
        aliasList.add(label);
      }
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
    return aliasList;
  }

  public static CaviumKey getKeyByHandle(long handle) throws CFM2Exception {
    // There is no direct method to load a key, but there is a method to load key attributes.
    // Using the key attributes and the handle, a new CaviumKey object can be created. This method shows
    // how to create a specific key type based on the attributes.
    byte[] keyAttribute = Util.getKeyAttributes(handle);
    CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);

    if (cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
      CaviumAESKey aesKey = new CaviumAESKey(handle, cka);
      return aesKey;
    } else if (
      cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA &&
      cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY
    ) {
      CaviumRSAPrivateKey privKey = new CaviumRSAPrivateKey(handle, cka);
      return privKey;
    } else if (
      cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA &&
      cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY
    ) {
      CaviumRSAPublicKey pubKey = new CaviumRSAPublicKey(handle, cka);
      return pubKey;
    } else if (
      cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC &&
      cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY
    ) {
      CaviumECPrivateKey privKey = new CaviumECPrivateKey(handle, cka);
      return privKey;
    } else if (
      cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC &&
      cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY
    ) {
      CaviumECPublicKey pubKey = new CaviumECPublicKey(handle, cka);
      return pubKey;
    } else if (
      cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_GENERIC_SECRET
    ) {
      CaviumKey key = new CaviumAESKey(handle, cka);
      return key;
    }

    return null;
  }

  public static Key getKey(String alias) {
    Key key = null;
    try {
      key = keyStore.getKey(alias, keystorePass.toCharArray());
    } catch (
      UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e
    ) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
    return key;
  }

  public static String getKeystoreProviderName() throws Exception {
    if (Objects.nonNull(keyStore)) {
      return keyStore.getProvider().getName();
    }
    throw new KeystoreProcessingException(
      KeymanagerErrorCode.KEYSTORE_NOT_INSTANTIATED.getErrorCode(),
      KeymanagerErrorCode.KEYSTORE_NOT_INSTANTIATED.getErrorMessage()
    );
  }

  public static void deleteKey(String alias) throws Exception {
    // alias = "RSA Wrapping Test:public";
    validatePKCS11KeyStore();
    try {
      // long[] handles = { 0 };
      // Util.findKey(alias, handles);
      // long handle = handles[0];
      // CaviumKey ck = getKeyByHandle(handle);
      // System.out.printf("Deleting key: " + alias);
      // System.out.println(" " + ck.getClass());
      CaviumKey ck = (CaviumKey) getKey(alias);
      Util.deleteKey(ck);
      keyStore.deleteEntry(alias);
    } catch (Exception e) {
      System.out.println("Failed to delete key: " + alias);
      // throw e;
    }
  }

  private static Provider setupProvider() throws Exception {
    provider = new com.cavium.provider.CaviumProvider();
    return provider;
  }

  private static SecretKey generateSymmetricKey(String alias) throws Exception {
    boolean isExtractable = true;
    boolean isPersistent = true;
    try {
      KeyGenerator generator = KeyGenerator.getInstance(
        symmetricKeyAlgorithm,
        provider
      );
      CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(
        symmetricKeyLength,
        alias,
        isExtractable,
        isPersistent
      );
      generator.init(aesSpec);
      return generator.generateKey();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new io.mosip.kernel.core.exception.NoSuchAlgorithmException(
        KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
        KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(),
        e
      );
    }
  }

  private static KeyPair generateKeyPair(
    String publicLabel,
    String privateLabel
  )
    throws Exception {
    boolean isExtractable = true;
    boolean isPersistent = true;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(
        asymmetricKeyAlgorithm,
        provider
      );
      // SecureRandom random = new SecureRandom();
      CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(
        asymmetricKeyLength,
        new BigInteger("65537"),
        publicLabel,
        privateLabel,
        isExtractable,
        isPersistent
      );
      generator.initialize(spec);
      return generator.generateKeyPair();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new io.mosip.kernel.core.exception.NoSuchAlgorithmException(
        KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
        KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(),
        e
      );
    }
  }

  private static void storeCertificate(
    String alias,
    Certificate[] chain,
    PrivateKey privateKey
  )
    throws Exception {
    // PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(privateKey, chain);
    char[] password = keystorePass.toCharArray();
    try {
      keyStore.setKeyEntry(alias, privateKey, password, chain);
      FileOutputStream outstream = new FileOutputStream(keystoreFile);
      keyStore.store(outstream, keystorePass.toCharArray());
      outstream.close();
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage()
      );
    }
  }

  public static void storeSymmetricKey(SecretKey secretKey, String alias)
    throws Exception {
    // SecretKeyEntry secret = new SecretKeyEntry(secretKey);
    char[] password = keystorePass.toCharArray();
    try {
      keyStore.setKeyEntry(alias, secretKey, password, null);
      // FileOutputStream outstream = new FileOutputStream(keystoreFile);
      // keyStore.store(outstream, keystorePass.toCharArray());
      // outstream.close();
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
  }

  private static void displayKeyInfo(CaviumKey key) {
    if (null != key) {
      System.out.printf(
        "Key handle %d with label %s\n",
        key.getHandle(),
        key.getLabel()
      );
      // Display whether the key can be extracted from the HSM.
      System.out.println("Is Key Extractable? : " + key.isExtractable());

      // Display whether this key is a token key.
      System.out.println("Is Key Persistent? : " + key.isPersistent());

      // The algorithm and size used to generate this key.
      System.out.println("Key Algo : " + key.getAlgorithm());
      System.out.println("Key Size : " + key.getSize());
    }
  }

  private static void displayAllKeys() throws Exception {
    List<String> keyAliases = new ArrayList<String>();
    keyAliases = getAllAlias();
    System.out.printf("The KeyStore contains %d keys\n", keyStore.size());
    System.out.println("Remaining keys");

    for (String keyAlias : keyAliases) {
      System.out.println("Key Alias: " + keyAlias);
    }
  }

  private static void validatePKCS11KeyStore() {
    if (KEYSTORE_TYPE_PKCS12.equals(keyStore.getType())) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.NOT_VALID_PKCS11_STORE_TYPE.getErrorCode(),
        KeymanagerErrorCode.NOT_VALID_PKCS11_STORE_TYPE.getErrorMessage()
      );
    }
  }

  public static Certificate generateCertificate(
    PrivateKey signPrivateKey,
    PublicKey publicKey,
    CertificateParameters certParams,
    X500Principal signerPrincipal
  ) {
    // Added this method because provider is not exposed from this class.
    return CertificateUtility.generateX509Certificate(
      signPrivateKey,
      publicKey,
      certParams,
      signerPrincipal,
      signAlgorithm,
      provider.getName()
    );
  }

  public static void storeAsymmetricKey(
    KeyPair keyPair,
    String alias,
    LocalDateTime validityFrom,
    LocalDateTime validityTo
  )
    throws Exception {
    X509Certificate[] chain = new X509Certificate[1];
    chain[0] =
      CertificateUtility.generateX509Certificate(
        keyPair.getPrivate(),
        keyPair.getPublic(),
        commonName,
        organizationalUnit,
        organization,
        country,
        validityFrom,
        validityTo,
        signAlgorithm == null
          ? KeymanagerConstant.SIGNATURE_ALGORITHM
          : signAlgorithm,
        provider == null ? "BC" : provider.getName()
      );
    storeCertificate(alias, chain, keyPair.getPrivate());
  }

  public static void storeCertificate(
    String alias,
    PrivateKey privateKey,
    Certificate certificate
  )
    throws Exception {
    try {
      // PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(
      //   privateKey,
      //   new Certificate[] { certificate }
      // );
      char[] password = keystorePass.toCharArray();
      keyStore.setKeyEntry(
        alias,
        privateKey,
        password,
        new Certificate[] { certificate }
      );
      FileOutputStream outstream = new FileOutputStream(keystoreFile);
      keyStore.store(outstream, keystorePass.toCharArray());
      outstream.close();
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
  }

  public static void generateAndStoreSymmetricKey(String alias)
    throws Exception {
    validatePKCS11KeyStore();
    SecretKey secretKey = generateSymmetricKey(alias);
    // SecretKeyEntry secret = new SecretKeyEntry(secretKey);
    char[] password = keystorePass.toCharArray();

    try {
      keyStore.setKeyEntry(alias, secretKey, password, null);
      FileOutputStream outstream = new FileOutputStream(keystoreFile);
      keyStore.store(outstream, keystorePass.toCharArray());
      outstream.close();
    } catch (KeyStoreException e) {
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        e.getMessage(),
        e
      );
    }
  }

  public static PrivateKeyEntry getAsymmetricKey(String alias)
    throws Exception {
    validatePKCS11KeyStore();
    PrivateKeyEntry privateKeyEntry = null;
    int i = 0;
    boolean isException = false;
    String expMessage = "";
    Exception exp = null;
    do {
      try {
        if (keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
          // LOGGER.debug(
          //   "sessionId",
          //   "KeyStoreImpl",
          //   "getAsymmetricKey",
          //   "alias is instanceof keystore"
          // );
          ProtectionParameter password = new PasswordProtection(
            keystorePass.toCharArray()
          );
          privateKeyEntry =
            (PrivateKeyEntry) keyStore.getEntry(alias, password);
          if (privateKeyEntry != null) {
            // LOGGER.debug(
            //   "sessionId",
            //   "KeyStoreImpl",
            //   "getAsymmetricKey",
            //   "privateKeyEntry is not null"
            // );
            break;
          }
        } else {
          throw new NoSuchSecurityProviderException(
            KeymanagerErrorCode.NO_SUCH_ALIAS.getErrorCode(),
            KeymanagerErrorCode.NO_SUCH_ALIAS.getErrorMessage() + alias
          );
        }
      } catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
        throw new KeystoreProcessingException(
          KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
          KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
          e.getMessage(),
          e
        );
      } catch (KeyStoreException kse) {
        isException = true;
        expMessage = kse.getMessage();
        exp = kse;
        // LOGGER.debug(
        //   "sessionId",
        //   "KeyStoreImpl",
        //   "getAsymmetricKey",
        //   expMessage
        // );
      }
      if (isException) {
        reloadProvider();
        isException = false;
      }
    } while (i++ < NO_OF_RETRIES);
    if (Objects.isNull(privateKeyEntry)) {
      // LOGGER.debug(
      //   "sessionId",
      //   "KeyStoreImpl",
      //   "getAsymmetricKey",
      //   "privateKeyEntry is null"
      // );
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        expMessage,
        exp
      );
    }
    return privateKeyEntry;
  }

  public static void generateAndStoreAsymmetricKey(
    String alias,
    String signKeyAlias,
    CertificateParameters certParams
  )
    throws Exception {
    validatePKCS11KeyStore();
    KeyPair keyPair = null;
    PrivateKey signPrivateKey = null;
    X500Principal signerPrincipal = null;
    if (Objects.nonNull(signKeyAlias)) {
      PrivateKeyEntry signKeyEntry = getAsymmetricKey(signKeyAlias);
      signPrivateKey = signKeyEntry.getPrivateKey();
      X509Certificate signCert = (X509Certificate) signKeyEntry.getCertificate();
      signerPrincipal = signCert.getSubjectX500Principal();
      keyPair = generateKeyPair(alias + ":public", alias); // To avoid key generation in HSM.
    } else {
      keyPair = generateKeyPair(alias + ":public", alias);
      signPrivateKey = keyPair.getPrivate();
    }
    X509Certificate x509Cert = CertificateUtility.generateX509Certificate(
      signPrivateKey,
      keyPair.getPublic(),
      certParams,
      signerPrincipal,
      signAlgorithm,
      provider.getName()
    );
    X509Certificate[] chain = new X509Certificate[] { x509Cert };
    storeCertificate(alias, chain, keyPair.getPrivate());
  }

  public static PrivateKey getPrivateKey(String alias) throws Exception {
    PrivateKeyEntry privateKeyEntry = getAsymmetricKey(alias);
    return privateKeyEntry.getPrivateKey();
  }

  public static PublicKey getPublicKey(String alias) throws Exception {
    PrivateKeyEntry privateKeyEntry = getAsymmetricKey(alias);
    Certificate[] certificates = privateKeyEntry.getCertificateChain();
    return certificates[0].getPublicKey();
  }

  public static SecretKey getSymmetricKey(String alias) throws Exception {
    validatePKCS11KeyStore();
    SecretKey secretKey = null;
    int i = 0;
    boolean isException = false;
    String expMessage = "";
    Exception exp = null;
    do {
      try {
        if (keyStore.entryInstanceOf(alias, SecretKeyEntry.class)) {
          ProtectionParameter password = new PasswordProtection(
            keystorePass.toCharArray()
          );
          SecretKeyEntry retrivedSecret = (SecretKeyEntry) keyStore.getEntry(
            alias,
            password
          );
          secretKey = retrivedSecret.getSecretKey();
          if (secretKey != null) {
            // LOGGER.debug(
            //   "sessionId",
            //   "KeyStoreImpl",
            //   "getSymmetricKey",
            //   "secretKey is not null"
            // );
            break;
          }
        } else {
          throw new NoSuchSecurityProviderException(
            KeymanagerErrorCode.NO_SUCH_ALIAS.getErrorCode(),
            KeymanagerErrorCode.NO_SUCH_ALIAS.getErrorMessage() + alias
          );
        }
      } catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
        throw new KeystoreProcessingException(
          KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
          KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
          e.getMessage(),
          e
        );
      } catch (KeyStoreException kse) {
        isException = true;
        expMessage = kse.getMessage();
        exp = kse;
        // LOGGER.debug(
        //   "sessionId",
        //   "KeyStoreImpl",
        //   "getSymmetricKey",
        //   expMessage
        // );
      }
      if (isException) {
        reloadProvider();
        isException = false;
      }
    } while (i++ < NO_OF_RETRIES);
    if (Objects.isNull(secretKey)) {
      // LOGGER.debug(
      //   "sessionId",
      //   "KeyStoreImpl",
      //   "getSymmetricKey",
      //   "secretKey is null"
      // );
      throw new KeystoreProcessingException(
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(),
        KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorMessage() +
        expMessage,
        exp
      );
    }
    return secretKey;
  }

  public static X509Certificate getCertificate(String alias) throws Exception {
    PrivateKeyEntry privateKeyEntry = getAsymmetricKey(alias);
    X509Certificate[] certificates = (X509Certificate[]) privateKeyEntry.getCertificateChain();
    return certificates[0];
  }
}
