package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCasePrivateBuckets {
	
	/*
	 * 		
	 * 			
	 * 			  RegularUserOne -> RegularIAMactOne ->  ReadData
	 * 						 ______________|				 |
	 * 						|								 |
	 * 		AdminUser -> AdminIAMact -> Bucket ->	Data -----
	 * 						|______________					 |
	 * 									   |				 |
	 * 			  RegularUserTwo -> RegularIAMactTwo ->  WriteData
	 * 				
	 * 		
	 * 		A bucket has three assigned users that depending on the privileges they have, have different rights 
	 * 		to the data stored on the bucket. For example, AdminUser will have complete access to the data on 
	 * 		the bucket; RegularUserOne can only read the data on the bucket; RegularUserTwo can only write the 
	 * 		data on the bucket.
	 * 
	 *  	Case #01: The AdminIAMact is compromised. The attacker should have complete control over the data.
	 *  
	 *  	Case #02: The RegularIAMactOne is compromised. The attacker should only be able to read data.
	 *  
	 *  	Case #03: The RegularIAMactTwo is compromised. The attacker should only be able to write data.
	 * 
	 */
	
	@Test
	   public void testbuckets_AdminIAMactCompromise() {
		
		  System.out.println("########## USE CASE TESTS FOR (PRIVATE) BUCKETS ##########");
		  
		  User AdminUser = new User("AdminUser");	
		  IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
		  Credentials AdminCred = new Credentials("AdminCred");
		  User RegularUserOne = new User("RegularUserOne");
		  IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
		  Credentials RegularCredOne = new Credentials("RegularCredOne");
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
		  bucket.addData(readData);
		  bucket.addAccount(AdminIAMact);
		  bucket.addAccount(RegularIAMactOne);
		  bucket.addAccount(RegularIAMactTwo);
		  
		  authServ.addAuthenticatedAccounts(AdminIAMact);
		  authServ.addAuthenticatedAccounts(RegularIAMactOne);
		  authServ.addAuthenticatedAccounts(RegularIAMactTwo);
		  
		  AdminUser.addAccounts(AdminIAMact);
		  AdminIAMact.addCredentials(AdminCred);
		  AdminIAMact.addReadData(data);
		  AdminIAMact.addWrittenData(data);
		  AdminIAMact.addDeletedData(data);
		  
		  RegularUserOne.addAccounts(RegularIAMactOne);
		  RegularIAMactOne.addCredentials(RegularCredOne);
		  RegularIAMactOne.addReadData(readData);
		  
		  RegularUserTwo.addAccounts(RegularIAMactTwo);
		  RegularIAMactTwo.addCredentials(RegularCredTwo);
		  RegularIAMactTwo.addWrittenData(writeData);

		  Attacker attacker = new Attacker();
	      attacker.addAttackPoint(bucket.connect);
	      attacker.addAttackPoint(AdminIAMact.compromise);
	      attacker.attack(); 
	      
	      System.out.println("~~~~~ CASE #01: ADMIN IAM ACCT COMPROMISE ~~~~~");
	      
		  data.read.assertCompromisedInstantaneously();
  		  data.write.assertCompromisedInstantaneously();					
  		  data.delete.assertCompromisedInstantaneously();
  		  readData.read.assertCompromisedInstantaneously();
  		  writeData.write.assertCompromisedInstantaneously();
  		 
	}
	
	@Test
	   public void testbuckets_RegularUserOneCompromise() {
		  
		  User AdminUser = new User("AdminUser");	
		  IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
		  Credentials AdminCred = new Credentials("AdminCred");
		  User RegularUserOne = new User("RegularUserOne");
		  IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
		  Credentials RegularCredOne = new Credentials("RegularCredOne");
		  User RegularUserTwo = new User("RegularUserTwo");
		  IAMaccount RegularIAMactTwo = new IAMaccount("RegularIAMactTwo");
		  Credentials RegularCredTwo = new Credentials("RegularCredTwo");
		  AuthenticationService authServ = new AuthenticationService();
		  Bucket bucket = new Bucket("bucket");
		  Data data = new Data("data");
		  Data readData = new Data("readData");
		  Data writeData = new Data("writeData");
		  
		  data.addContainedData(readData);
		  data.addContainedData(writeData);
		  bucket.addData(data);
		  bucket.addData(readData);
		  bucket.addData(readData);
		  bucket.addAccount(AdminIAMact);
		  bucket.addAccount(RegularIAMactOne);
		  bucket.addAccount(RegularIAMactTwo);
		  
		  authServ.addAuthenticatedAccounts(AdminIAMact);
		  authServ.addAuthenticatedAccounts(RegularIAMactOne);
		  authServ.addAuthenticatedAccounts(RegularIAMactTwo);
		  
		  AdminUser.addAccounts(AdminIAMact);
		  AdminIAMact.addCredentials(AdminCred);
		  AdminIAMact.addReadData(data);
		  AdminIAMact.addWrittenData(data);
		  AdminIAMact.addDeletedData(data);
		  
		  RegularUserOne.addAccounts(RegularIAMactOne);
		  RegularIAMactOne.addCredentials(RegularCredOne);
		  RegularIAMactOne.addReadData(readData);
		  
		  RegularUserTwo.addAccounts(RegularIAMactTwo);
		  RegularIAMactTwo.addCredentials(RegularCredTwo);
		  RegularIAMactTwo.addWrittenData(writeData);

		  Attacker attacker = new Attacker();
	      attacker.addAttackPoint(bucket.connect);
	      attacker.addAttackPoint(RegularIAMactOne.compromise);
	      attacker.attack(); 
	      
	      System.out.println("~~~~~ CASE #02: READ ONLY RIGHTS IAM ACCT ('RegularIAMactOne') COMPROMISE ~~~~~");
	      
	      data.read.assertUncompromised();
		  data.write.assertUncompromised();					
		  data.delete.assertUncompromised();
		  readData.read.assertCompromisedInstantaneously();
		  writeData.write.assertUncompromised();
		 
	}
	
	@Test
	   public void testbuckets_RegularIAMactTwoCompromise() {
		  
		  User AdminUser = new User("AdminUser");	
		  IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
		  Credentials AdminCred = new Credentials("AdminCred");
		  User RegularUserOne = new User("RegularUserOne");
		  IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
		  Credentials RegularCredOne = new Credentials("RegularCredOne");
		  User RegularUserTwo = new User("RegularUserTwo");
		  IAMaccount RegularIAMactTwo = new IAMaccount("RegularIAMactTwo");
		  Credentials RegularCredTwo = new Credentials("RegularCredTwo");
		  AuthenticationService authServ = new AuthenticationService();
		  Bucket bucket = new Bucket("bucket");
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
		  bucket.addAccount(RegularIAMactTwo);
		  
		  authServ.addAuthenticatedAccounts(AdminIAMact);
		  authServ.addAuthenticatedAccounts(RegularIAMactOne);
		  authServ.addAuthenticatedAccounts(RegularIAMactTwo);
		  
		  AdminUser.addAccounts(AdminIAMact);
		  AdminIAMact.addCredentials(AdminCred);
		  AdminIAMact.addReadData(data);
		  AdminIAMact.addWrittenData(data);
		  AdminIAMact.addDeletedData(data);
		  
		  RegularUserOne.addAccounts(RegularIAMactOne);
		  RegularIAMactOne.addCredentials(RegularCredOne);
		  RegularIAMactOne.addReadData(readData);
		  
		  RegularUserTwo.addAccounts(RegularIAMactTwo);
		  RegularIAMactTwo.addCredentials(RegularCredTwo);
		  RegularIAMactTwo.addWrittenData(writeData);

		  Attacker attacker = new Attacker();
	      attacker.addAttackPoint(bucket.connect);
	      attacker.addAttackPoint(RegularIAMactTwo.compromise);
	      attacker.attack(); 
	      
	      System.out.println("~~~~~ CASE #03: WRITE ONLY RIGHTS IAM ACCT ('RegularIAMactTwo') COMPROMISE ~~~~~");
	      
	      data.read.assertUncompromised();
		  data.write.assertUncompromised();					
		  data.delete.assertUncompromised();
		  readData.read.assertUncompromised();
		  writeData.write.assertCompromisedInstantaneously();
		 
	}
	
	@After
	   public void deleteModel() {
	           Asset.allAssets.clear();
	           AttackStep.allAttackSteps.clear();
	           Defense.allDefenses.clear();
	   }
   
}
