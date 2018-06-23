package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCasePublicBuckets {
	
	/*
	 * 			
	 * 		AdminUser -> AdminIAMact -> PublicBucket -> Data
	 * 										 ^
	 * 										 |
	 * 									  Attacker
	 * 
	 * 
	 * 		An attacker runs a dictionary attack to find possible bucket names and attempts to break into
	 * 		them if they are public. 
	 * 
	 * 		Note: The attacker should also be able to read/write on the data stored in the bucket, depending
	 * 		on whether that data has been set public or private by the owner, but since we do not have the
	 * 		distinction for data yet, we model this by saying that if such an attack is successful, the attacker
	 * 		should be able to request access on the data but the actual read/write would be as of yet uncompromised.  
	 * 
	 */
	
	@Test
	   public void testpublicbuckets() {
		
		System.out.println("########## USE CASE TESTS FOR (PUBLIC) BUCKETS ##########");
		  
		  User AdminUser = new User("AdminUser");	
		  IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
		  Credentials AdminCred = new Credentials("AdminCred");
		  AuthenticationService authServ = new AuthenticationService();
		  Bucket bucket = new Bucket("bucket", false, true);					//	Public Bucket
		  Data data = new Data("data");

		  bucket.addData(data);
		  bucket.addAccount(AdminIAMact);
		  
		  authServ.addAuthenticatedAccounts(AdminIAMact);
		  
		  AdminUser.addAccounts(AdminIAMact);
		  AdminIAMact.addCredentials(AdminCred);
		  AdminIAMact.addReadData(data);
		  AdminIAMact.addWrittenData(data);
		  AdminIAMact.addDeletedData(data);

		  Attacker attacker = new Attacker();
	      attacker.addAttackPoint(bucket.attemptConnectPublicBucket);
	      attacker.attack();
	      
	      bucket.bruteForceAttack.assertCompromisedWithEffort();
	      data.requestAccess.assertCompromisedWithEffort();
	      
	      data.read.assertUncompromised();						//
	      data.write.assertUncompromised();						//	Read and write on data depends on whether the data is public/private
		  data.delete.assertUncompromised();					//
		 
	}
	
	@After
	   public void deleteModel() {
	           Asset.allAssets.clear();
	           AttackStep.allAttackSteps.clear();
	           Defense.allDefenses.clear();
	   }
   
}
