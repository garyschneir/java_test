package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;
import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import com.ubiqsecurity.UbiqFactory;
import java.util.concurrent.ExecutionException;
import java.util.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runners.*;
import org.junit.FixMethodOrder;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UbiqFPEEncryptTest
{
    static UbiqCredentials ubiqCredentials = null;    
    static UbiqWebServices ubiqWebServices = null; 
    static boolean available_ALPHANUM_SSN = false;
    static boolean available_BIRTH_DATE = false;
    static boolean available_GENERIC_STRING = false;
    static boolean available_SO_ALPHANUM_PIN = false;
    static boolean available_SSN = false;
    
    
    public boolean skipThisFFS(String ffs_name) {
        switch(ffs_name)
        {
            case "ALPHANUM_SSN":
                if (available_ALPHANUM_SSN == false) {
                    System.out.println("-------------- Skipped test for " + ffs_name);
                    return true;
                }
                break;
            case "BIRTH_DATE":
                if (available_BIRTH_DATE == false) {
                    System.out.println("-------------- Skipped test for " + ffs_name);
                    return true;
                }
                break;
            case "GENERIC_STRING":
                if (available_GENERIC_STRING == false) {
                    System.out.println("-------------- Skipped test for " + ffs_name);
                    return true;
                }
                break;
            case "SO_ALPHANUM_PIN":
                if (available_SO_ALPHANUM_PIN == false) {
                    System.out.println("-------------- Skipped test for " + ffs_name);
                    return true;
                }
                break;
            case "SSN":
                if (available_SSN == false) {
                    System.out.println("-------------- Skipped test for " + ffs_name);
                    return true;
                }
                break;
            default:
                System.out.println("-------------- Skipped test for " + ffs_name);
                return true;
        }
        return false;
    }   

    public UbiqFPEEncryptTest() {
        if ((ubiqCredentials != null) && (ubiqWebServices != null)) {
            return;
        }
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqWebServices = new UbiqWebServices(ubiqCredentials);
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
        } 

    }

    static void testCycleEncryption(String ffs_name, String plainText, UbiqCredentials ubiqCredentials) {
        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
            String result = ubiqEncryptDecrypt.encryptFPE(ffs_name, plainText, null); 
            result = ubiqEncryptDecrypt.decryptFPE(ffs_name, result, null);
        }    
    }
    
    public boolean validateFFSModelbeforeUse(String ffs_name) {
        try {
            FFSRecordResponse ffsRecordResponse= ubiqWebServices.getFFSDefinition(ffs_name);
            
            if (ffsRecordResponse==null) {
                return false;
            } else {
                return true;
            }
        } catch (Exception ex) {
            return false;
        } 
    }
    
    
    // this tests are name sorted such that they are always performed first by junit4
    @Test
    public void _1_encryptFPE_verifyIfAvailableToTest() {
        if (validateFFSModelbeforeUse("ALPHANUM_SSN")) {
            available_ALPHANUM_SSN= true;
            System.out.println("Will test ALPHANUM_SSN");
        } else {
            System.out.println("Will skip test for ALPHANUM_SSN");
        }
        assertEquals(true, true); 
    }    

    @Test
    public void _2_encryptFPE_verifyIfAvailableToTest() {
        if (validateFFSModelbeforeUse("BIRTH_DATE")) {
            available_BIRTH_DATE= true;
            System.out.println("Will test BIRTH_DATE");
        } else {
            System.out.println("Will skip test for BIRTH_DATE");
        }
        assertEquals(true, true); 
    }    

    @Test
    public void _3_encryptFPE_verifyIfAvailableToTest() {
        if (validateFFSModelbeforeUse("GENERIC_STRING")) {
            available_GENERIC_STRING= true;
            System.out.println("Will test GENERIC_STRING");
        } else {
            System.out.println("Will skip test for GENERIC_STRING");
        }
        assertEquals(true, true); 
    }    

    @Test
    public void _4_encryptFPE_verifyIfAvailableToTest() {
        if (validateFFSModelbeforeUse("SO_ALPHANUM_PIN")) {
            available_SO_ALPHANUM_PIN= true;
            System.out.println("Will test SO_ALPHANUM_PIN");
        } else {
            System.out.println("Will skip test for SO_ALPHANUM_PIN");
        }
        assertEquals(true, true); 
    }    

    @Test
    public void _5_encryptFPE_verifyIfAvailableToTest() {
        if (validateFFSModelbeforeUse("SSN")) {
            available_SSN= true;
            System.out.println("Will test SSN");
        } else {
            System.out.println("Will skip test for SSN");
        }
        assertEquals(true, true); 
    }    

    @Test
    public void _6_encryptFPE_verifyIfAvailableToTestTester() {
        if (validateFFSModelbeforeUse("WILL NOT DO")) {
            assertEquals(true, false); 
        } else {
            assertEquals(true, true); 
        }        
    }    

    // the following tests may be performed in any order
    @Test
    public void encryptFPE_1() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }


    @Test
    public void encryptFPE_2() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = " 01&23-456-78-90";
                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }






    @Test
    public void encryptFPE_BIRTH_DATE_1() {
        if (skipThisFFS("BIRTH_DATE") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "2006-05-01";
                String cipher = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("BIRTH_DATE", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }


    @Test
    public void encryptFPE_GENERIC_STRING() {
        if (skipThisFFS("GENERIC_STRING") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
                String cipher = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("GENERIC_STRING", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }


    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_1() {
        if (skipThisFFS("SO_ALPHANUM_PIN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "1234";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }


    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_2() {
        if (skipThisFFS("SO_ALPHANUM_PIN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "ABCDE";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }



    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_3() {
        if (skipThisFFS("SO_ALPHANUM_PIN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "ABCD";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }    
    }





    @Test
    public void encryptFPE_MultipleCachedKeys() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            return;
        }
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                String cipher2 = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1); 
                
                assertEquals(cipher, cipher2);  
                
                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                String decrypted2 = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, null);
                
                
                assertEquals(decrypted, decrypted2);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
          ex.printStackTrace();
            fail(ex.toString());
           
        }    
    }




 


    @Test(expected = Exception.class)
    public void encryptFPE_InvalidFFS() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }    
        
        testCycleEncryption("ERROR FFS", "ABCDEFGHI", ubiqCredentials);  
    }



    @Test(expected = Exception.class)
    public void encryptFPE_InvalidCredentials() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.createCredentials("a","b","c", "d");
        } catch (Exception ex) {
        }    
        
        testCycleEncryption("ALPHANUM_SSN", "ABCDEFGHI", ubiqCredentials);  
    }



    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_PT_CT() {
        if (skipThisFFS("SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }    

        testCycleEncryption("SSN", " 123456789$", ubiqCredentials);      
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_1() {
        if (skipThisFFS("SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("SSN", " 1234", ubiqCredentials);           
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_2() {
        if (skipThisFFS("SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }    

        testCycleEncryption("SSN", " 12345678901234567890", ubiqCredentials);           
    }
 

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_1() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId().substring(0, 1),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_2() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey().substring(0, 1),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);     
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_3() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey().substring(0, 1),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);     
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_4() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "pi.ubiqsecurity.com" );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);     
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_5() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "ps://api.ubiqsecurity.com" );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);     
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_6() {
        if (skipThisFFS("ALPHANUM_SSN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
            ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "https://google.com" );
        } catch (Exception ex) {
        } 
        
        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);     
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_keynum() {
        if (skipThisFFS("SO_ALPHANUM_PIN") == true) {
            throw new IllegalArgumentException("FFS not testable");
        }
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }    
        
        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", null); 
                StringBuilder newcipher = new StringBuilder(cipher);
                newcipher.setCharAt(0, '}');
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", newcipher.toString(), null);
        }
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Error_handling_invalid_ffs() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }    
        
        testCycleEncryption("ERROR_MSG", " 01121231231231231& 1 &2311200 ", ubiqCredentials);  
    }


}
