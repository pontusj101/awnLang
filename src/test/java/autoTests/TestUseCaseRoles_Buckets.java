package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseRoles_Buckets {
	
	/*
	 * 								Role -------------------------------------
	 * 								  |										 |
	 * 			 RegularUserOne -> RegularIAMactOne  ->  ReadData			 |
	 * 						 ______________|				 |				 |
	 * 						|								 |				 |
	 * 		AdminUser -> AdminIAMact -> Bucket ->	Data -----				 |
	 * 						|______________					 |				 |
	 * 									   |				 |				 |
	 * 			  RegularUserTwo -> RegularIAMactTwo ->  WriteData	<---------		
	 * 
	 * 		
	 * 		A bucket has three assigned users that depending on the privileges they have, have different rights 
	 * 		to the data stored on the bucket. For example, AdminUser will have complete access to the data on 
	 * 		the bucket; RegularUserOne can only read the data on the bucket; RegularUserTwo can only write the 
	 * 		data on the bucket.
	 * 
	 * 		However, RegularUserOne can assume a role on the bucket to get the write rights to the data stored
	 * 		on the bucket.
	 * 
	 * 		Attacker is able to compromise RegularUserOne's IAM account.
	 * 
	 * 
	 */

   @Test
   public void testroles_buckets() {
	   
	   System.out.println("########## USE CASE TESTS FOR ROLES (BUCKETS) ##########");
	  
	   User AdminUser = new User("AdminUser");	
	   IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
	   Credentials AdminCred = new Credentials("AdminCred");
	   User RegularUserOne = new User("RegularUserOne");
	   IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
	   Credentials RegularCredOne = new Credentials("RegularCredOne");
	   Role role = new Role("role");
	   User RegularUserTwo = new User("RegularUserTwo");
	   IAMaccount RegularIAMactTwo = new IAMaccount("RegularIAMactTwo");
	   Credentials RegularCredTwo = new Credentials("RegularCredTwo");
	   AuthenticationService authServ = new AuthenticationService();
	   Bucket bucket = new Bucket("bucket", true, true);
	   Data data = new Data("data");
	   Data readData = new Data("readData");
	   Data writeData = new Data("writeData");
	   
	   data.addContainedData(readData);
	   data.addContainedData(writeData);
	   bucket.addData(data);
	   bucket.addData(readData);
	   bucket.addData(writeData);
	   bucket.addAccount(AdminIAMact);
	   bucket.addAccount(RegularIAMactOne);
	   bucket.addAccount(role);
	   bucket.addAccount(RegularIAMactTwo);
	   
	   authServ.addAuthenticatedAccounts(AdminIAMact);
	   authServ.addAuthenticatedAccounts(RegularIAMactOne);
	   authServ.addAuthenticatedAccounts(role);
	   authServ.addAuthenticatedAccounts(RegularIAMactTwo);
	   
	   AdminUser.addAccounts(AdminIAMact);
	   AdminIAMact.addCredentials(AdminCred);
	   AdminIAMact.addReadData(data);
	   AdminIAMact.addWrittenData(data);
	   AdminIAMact.addDeletedData(data);
	   
	   RegularUserOne.addAccounts(RegularIAMactOne);
	   RegularIAMactOne.addCredentials(RegularCredOne);
	   RegularIAMactOne.addReadData(readData);
	   RegularIAMactOne.addAuthenticatees(role);
	   role.addWrittenData(writeData);
	   
	   RegularUserTwo.addAccounts(RegularIAMactTwo);
	   RegularIAMactTwo.addCredentials(RegularCredTwo);
	   RegularIAMactTwo.addWrittenData(writeData);
	  
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(bucket.connect);
	   attacker.addAttackPoint(RegularIAMactOne.compromise);
	   attacker.attack();
	   
	   data.read.assertUncompromised();
	   data.write.assertUncompromised();					
	   data.delete.assertUncompromised();
	   readData.read.assertCompromisedInstantaneously();
	   role.authenticate.assertCompromisedInstantaneously();
	   writeData.write.assertCompromisedInstantaneously();
	  
      }
   
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
