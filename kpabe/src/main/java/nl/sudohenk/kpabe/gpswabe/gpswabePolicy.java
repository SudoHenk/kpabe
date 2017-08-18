package nl.sudohenk.kpabe.gpswabe;

import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class gpswabePolicy {
	/*serialized*/
	/* k=1 if leaf, otherwise threshold */
	int k;
	/* attribute string if leaf, otherwise null */
	String attr;
	Element D;			/* G_1 only for leaves */
	/* array of gpswabePolicy and length is 0 for leaves */
	gpswabePolicy[] children;
	
	/* Serilization cost */
	int serilize_cost;

	/* only used during encryption */
	gpswabePolynomial q;

	/* only used during decryption */
	boolean satisfiable;
	int min_leaves;
	int attri;
	ArrayList<Integer> satl = new ArrayList<Integer>();
	
	
	public gpswabePolicy() {
    }
	
	
	
	public gpswabePolicy(String attr, int k, gpswabePolicy[] children) {
        super();
        this.k = k;
        this.attr = attr;
        this.children = children;
    }




    public String getAttr() {
        return attr;
    }




    public void setAttr(String attr) {
        this.attr = attr;
    }




    public int getK() {
        return k;
    }




    public void setK(int k) {
        this.k = k;
    }




    public gpswabePolicy[] getChildren() {
        return children;
    }




    public void setChildren(gpswabePolicy[] children) {
        this.children = children;
    }




    @Override
	public String toString() {
	    String childOutput = "";
	    for (int i = 0; i < children.length; i++) {
            childOutput += children[i].toString();
        }
	    return "Policy[attr=\""+attr+"\", k="+k+", children=["+childOutput+"]]";
	}
}