package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class CryptographicKeyTest {

   @Test
   public void testCryptographicKey() {
	   
	   System.out.println("########## TESTS FOR ENCRYPTED DATA ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   Information information = new Information();
	   EncryptedData encryptedData = new EncryptedData();
	   CryptographicKey cryptKey = new CryptographicKey();
	   Bucket bucket = new Bucket();
	   IAMaccount iamaccount = new IAMaccount();

	   bucket.addData(encryptedData);
	   encryptedData.addInformation(information);
	   encryptedData.addDecryptionKeys(cryptKey);
	   encryptedData.addEncryptionKeys(cryptKey);
	   bucket.addAccount(iamaccount);
	   encryptedData.addReadAccess(iamaccount);
	   encryptedData.addWriteAccess(iamaccount);	

	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(iamaccount.compromise);
	   attacker.addAttackPoint(cryptKey.read);
	   attacker.addAttackPoint(bucket.connect);      
	   attacker.attack();

	   cryptKey.compromise.assertCompromisedWithEffort();
	   encryptedData.read.assertCompromisedWithEffort();
	   encryptedData.write.assertCompromisedWithEffort();
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


