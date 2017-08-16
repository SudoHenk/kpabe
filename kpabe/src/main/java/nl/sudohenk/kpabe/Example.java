package nl.sudohenk.kpabe;

import nl.sudohenk.kpabe.KeyPolicyAttributeBasedEncryption;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Example {

    
    public static void main(String[] args) throws Exception {
        Logger logger = LoggerFactory.getLogger(Example.class);
        
        String test_folder = "C://Users/Sander/git/kpabe/example/";
        String curveparamsFileLocation = test_folder + "curveparams";
        
        KeyPolicyAttributeBasedEncryption kpabe = new KeyPolicyAttributeBasedEncryption();
        String pubfile = test_folder + "publickey";
        String mskfile = test_folder + "mastersecretkey";
        String[] attrs_univ = {"application1", "module1", "solution1"};
        kpabe.setup(pubfile, mskfile, attrs_univ, curveparamsFileLocation);
        
        String prvfile = test_folder + "policy";
        String policy = "solution1 application1 module1 2of3";
        
        kpabe.keygen(pubfile, mskfile, prvfile, policy);
        
        String inputfile = test_folder + "test";
        String encfile = test_folder + "test.enc.txt";
        String decfile = test_folder + "test.dec.txt";
        try {
            kpabe.enc(pubfile, inputfile, attrs_univ, encfile);
        } catch(Exception e) {
            logger.error("Encryption failed");
        }
        
        
        try {
            kpabe.dec(pubfile, prvfile, encfile, decfile);
        } catch(Exception e) {
            logger.error("Decryption failed");
        }
    }
}
