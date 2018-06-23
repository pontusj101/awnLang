package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class BucketTest {

   @Test
   public void testBucket_noDefenses() {
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE ~~~~~");
	   
	   Bucket bucket = new Bucket();
	   IAMaccount iamaccount = new IAMaccount();
	   
	   iamaccount.addAccessedBuckets(bucket);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(bucket.connect);
	   attacker.addAttackPoint(iamaccount.compromise);
	   attacker.addAttackPoint(bucket.attemptConnectPublicBucket);		//	since it's a private bucket, an attacker should not be able to to do dictionary attacks--
	   attacker.attack();
	   
	   iamaccount.compromisedAccess.assertCompromisedInstantaneously();
	   bucket.compromisedAccess.assertCompromisedInstantaneously();
	   bucket.authenticate.assertCompromisedInstantaneously();
	   bucket.authenticatedAccess.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   bucket._machineAccess.assertCompromisedInstantaneously();
	   bucket.denialOfService.assertCompromisedInstantaneously();
	   bucket.bruteForceAttack.assertCompromisedWithEffort();			//	--and brute force their way into the contents of the bucket
	   
   }
   
   @Test
   public void testBucket_allDefenses() {
	   
	   System.out.println("########## TESTS FOR BUCKET ##########");
	   
	   System.out.println("~~~~~ ALL DEFENSES IN PLACE ~~~~~");
	   
	   Bucket bucket = new Bucket(true, true);
	   IAMaccount iamaccount = new IAMaccount();
	   
	   bucket.addAccount(iamaccount);
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(bucket.connect);
	   attacker.addAttackPoint(iamaccount.compromise);
	   attacker.attack();
	   
	   iamaccount.compromisedAccess.assertCompromisedInstantaneously();
	   bucket.compromisedAccess.assertCompromisedInstantaneously();
	   bucket.authenticate.assertCompromisedInstantaneously();
	   bucket.authenticatedAccess.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   bucket._machineAccess.assertCompromisedInstantaneously();
	   bucket.denialOfService.assertCompromisedInstantaneously();
	   bucket.attemptConnectPublicBucket.assertUncompromised();			//	since it's a private bucket, an attacker should not be able to to do dictionary attacks--
	   bucket.bruteForceAttack.assertUncompromised();					//	--and brute force their way into the contents of the bucket
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


