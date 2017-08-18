package nl.sudohenk.kpabe;

import it.unisa.dia.gas.jpbc.Element;
import nl.sudohenk.kpabe.gpswabe.SerializeUtils;
import nl.sudohenk.kpabe.gpswabe.gpswabe;
import nl.sudohenk.kpabe.gpswabe.gpswabeCph;
import nl.sudohenk.kpabe.gpswabe.gpswabeCphKey;
import nl.sudohenk.kpabe.gpswabe.gpswabeMsk;
import nl.sudohenk.kpabe.gpswabe.gpswabePolicy;
import nl.sudohenk.kpabe.gpswabe.gpswabePrv;
import nl.sudohenk.kpabe.gpswabe.gpswabePub;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

/**
 * @param args
 * @author Liang Zhang(lz278@cornell.edu)
 */
public class KeyPolicyAttributeBasedEncryption{
	public void setup(String pubfile, String mskfile, String[] attrs_univ, String curveparamsFileLocation) throws IOException, ClassNotFoundException {
		byte[] pub_byte, msk_byte;
		gpswabePub pub = new gpswabePub();
		gpswabeMsk msk = new gpswabeMsk();
		gpswabe.setup(pub, msk, attrs_univ, curveparamsFileLocation);

		/* store gpswabePub into pubfile */
		pub_byte = SerializeUtils.serializegpswabePub(pub);
		Common.spitFile(pubfile, pub_byte);

		/* store gpswabeMsk into mskfile */
		msk_byte = SerializeUtils.serializegpswabeMsk(msk);
		Common.spitFile(mskfile, msk_byte);
	}
	
	public void keygen(String pubfile, String mskfile, String prvfile, 
	    gpswabePolicy policy) throws Exception {
		gpswabePub pub;
		gpswabeMsk msk;
		gpswabePrv prv;
		byte[] pub_byte, msk_byte, prv_byte;

		/* get gpswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializegpswabePub(pub_byte);

		/* get gpswabeMsk from mskfile */
		msk_byte = Common.suckFile(mskfile);
		msk = SerializeUtils.unserializegpswabeMsk(pub, msk_byte);

		/*String policy = LangPolicy.parsePolicy(attr_str);*/
		prv = gpswabe.keygen(pub, msk, policy);

		/* store gpswabePrv into prvfile */
		prv_byte = SerializeUtils.serializegpswabePrv(prv);
		Common.spitFile(prvfile, prv_byte);
	}
	
	public byte[] enc(String pubfile, byte[] plaintext, String[] attrs) throws Exception {
		gpswabePub pub;
		gpswabeCphKey cphKey;
		gpswabeCph cph;
		byte[] plt;
		byte[] cphBuf;
		byte[] aesBuf;
		byte[] pub_byte;
		Element m;

		/* get gpswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializegpswabePub(pub_byte);

		cphKey = gpswabe.enc(pub,attrs);
		m=cphKey.key;
		cph=cphKey.cph;
		System.err.println("m = "+m.toString());

		if (cph == null) {
			System.out.println("Error happed in enc");
			System.exit(0);
		}

		cphBuf = SerializeUtils.gpswabeCphSerialize(cph);

		/* read file to encrypted */
		plt = plaintext;
		aesBuf = AESCoder.encrypt(m.toBytes(), plt);
		// PrintArr("element: ", m.toBytes());
		// Common.writeKpabeFile(encfile, cphBuf, aesBuf);
		return Common.writeKpabeStream(cphBuf, aesBuf);
	}
	
	public byte[] dec(String pubfile, String prvfile, byte[] ciphertext) throws Exception {
		byte[] aesBuf, cphBuf;
		byte[] plt;
		byte[] prv_byte;
		byte[] pub_byte;
		byte[][] tmp;
		gpswabeCph cph;
		gpswabePrv prv;
		gpswabePub pub;

		/* get gpswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializegpswabePub(pub_byte);

		/* read ciphertext */
		tmp = Common.readKpabeStream(ciphertext);
		aesBuf = tmp[0];
		cphBuf = tmp[1];
		cph = SerializeUtils.gpswabeCphUnserialize(pub, cphBuf);

		/* get gpswabePrv from prvfile */
		prv_byte = Common.suckFile(prvfile);
		prv = SerializeUtils.unserializegpswabePrv(pub, prv_byte);

		Element m=gpswabe.dec(pub,  prv, cph);
		if (m!=null) {
			plt = AESCoder.decrypt(m.toBytes(), aesBuf);
			//Common.spitFile(decfile, plt);
			return plt;
		} else {
			System.exit(0);
		}
        return null;
	}
	
	
}
