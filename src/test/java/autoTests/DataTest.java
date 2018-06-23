package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class DataTest {

   @Test
   public void testData() {
	   
	   System.out.println("########## TESTS FOR DATA ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   Bucket bucket = new Bucket();
	   IAMaccount iamaccount = new IAMaccount();
	   Data data = new Data();
	   
	   bucket.addAccount(iamaccount);
	   bucket.addData(data);
	   iamaccount.addReadData(data);
	   iamaccount.addWrittenData(data);
	   iamaccount.addDeletedData(data);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(bucket.connect);
	   attacker.addAttackPoint(iamaccount.compromise);
	   attacker.attack();
	   
	   bucket.authenticatedAccess.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   bucket._machineAccess.assertCompromisedInstantaneously();
	   data.requestAccess.assertCompromisedInstantaneously();
	   data.anyAccountRead.assertCompromisedInstantaneously();
	   data.read.assertCompromisedInstantaneously();
	   data.anyAccountWrite.assertCompromisedInstantaneously();
	   data.write.assertCompromisedInstantaneously();
	   data.anyAccountDelete.assertCompromisedInstantaneously();
	   data.delete.assertCompromisedInstantaneously();
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


