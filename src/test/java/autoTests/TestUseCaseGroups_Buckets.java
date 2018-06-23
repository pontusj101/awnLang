package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseGroups_Buckets {
	
	/*								
	 * 
	 * 															 ___________________________________
	 * 															|									|
	 * 															|									|
	 * 				 								 -> SpecialUserIAMact -> 						|
	 * 												|					    |						|
	 * 						 ---------> ReadOnly ---|					    |--->  ReadData			|
	 * 						 |			   |		|					    |						|
	 *  		 			 |			   |		 ->  RegularIAMactOne -> 						|
	 * 						 |			   |				 |										|
	 * 						 |			   |				 |										|
	 * 		AdminUser -> AdminIAMact	 Bucket -> Data ------										|
	 * 						 |			   |				 |										|
	 * 						 |			   |                 |										|
	 * 						 |			   |                 |										|
	 * 						 |			   |				 |										|
	 * 			  			 --------->	WriteOnly -> RegularIAMactTwo -> WriteData	<----------------
	 * 			
	 * 			  
	 * 
	 * 		An IAM account, AdminIAMact, created and assigned two groups to a bucket, ReadOnly and WriteOnly. Members of 
	 * 		the ReadOnly group can only read data stored on the bucket while members of the WriteOnly group can only write 
	 * 		data stored on the bucket. In addition to AdminIAMact, that is member of both ReadOnly and WriteOnly, ReadOnly
	 * 		has SpecialUserIAMact and RegularIAMactOne as its members while WriteOnly has only RegularIAMactTwo as its
	 * 		member.
	 * 
	 * 		The reason why SpecialUserIAMact is, well, special is that apart from read rights on the data stored on the bucket (that
	 * 		it got from being member of the ReadOnly group), it also has write rights on the data stored on the bucket without (being
	 * 		member of the WriteOnly group).
	 * 
	 *  	Case #01: The attacker is able to compromise RegularIAMactOne, and should only be able to read data on the bucket.
	 *  
	 *  	Case #02: The attacker is able to compromise SpecialUserIAMact, and should not only be able to read data but also write to it.
	 *  
	 * 
	 */
	
	
   @Test
   public void testgroups_simplecompromise() {
	   
	   User AdminUser = new User("AdminUser");	
	   IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
	   Credentials AdminCred = new Credentials("AdminCred");
	   User RegularUserOne = new User("RegularUserOne");
	   IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
	   Credentials RegularCredOne = new Credentials("RegularCredOne");
	   User RegularUserTwo = new User("RegularUserTwo");
	   IAMaccount RegularIAMactTwo = new IAMaccount("RegularIAMactTwo");
	   Credentials RegularCredTwo = new Credentials("RegularCredTwo");
	   User SpecialUser = new User("SpecialUser");
	   IAMaccount SpecialUserIAMact = new IAMaccount("SpecialUserIAMact");
	   Credentials SpecialUserCred = new Credentials("SpecialUserCred");
	   AuthenticationService authServ = new AuthenticationService("authServ");
	   Group ReadOnly = new Group("ReadOnly");
	   Group WriteOnly = new Group("WriteOnly");
	   Bucket bucket = new Bucket("bucket", true, true);
	   Data data = new Data("data");
	   Data readData = new Data("readData");
	   Data writeData = new Data("writeData");
	   
	   AdminUser.addAccounts(AdminIAMact);
	   AdminIAMact.addCredentials(AdminCred);
	   
	   RegularUserOne.addAccounts(RegularIAMactOne);
	   RegularIAMactOne.addCredentials(RegularCredOne);
	   
	   RegularUserTwo.addAccounts(RegularIAMactTwo);
	   RegularIAMactTwo.addCredentials(RegularCredTwo);
	   
	   SpecialUser.addAccounts(SpecialUserIAMact);
	   SpecialUserIAMact.addCredentials(SpecialUserCred);
	   
	   authServ.addAuthenticatedAccounts(AdminIAMact);
	   authServ.addAuthenticatedAccounts(RegularIAMactOne);
	   authServ.addAuthenticatedAccounts(RegularIAMactTwo);
	   authServ.addAuthenticatedAccounts(SpecialUserIAMact);
	   
	   AdminIAMact.addCreatedIAMgroups(ReadOnly);
	   AdminIAMact.addCreatedIAMgroups(WriteOnly);
	   
	   data.addContainedData(readData);
	   data.addContainedData(writeData);
	   bucket.addData(data);
	   bucket.addData(readData);
	   bucket.addData(writeData);
	   bucket.addAccount(ReadOnly);
	   bucket.addAccount(WriteOnly);

	   ReadOnly.addMemberIAMaccounts(AdminIAMact);
	   ReadOnly.addMemberIAMaccounts(RegularIAMactOne);
	   ReadOnly.addMemberIAMaccounts(SpecialUserIAMact);
	   ReadOnly.addReadData(readData);
	   
	   WriteOnly.addMemberIAMaccounts(AdminIAMact);
	   WriteOnly.addMemberIAMaccounts(RegularIAMactTwo);
	   WriteOnly.addWrittenData(writeData);
	   
	   SpecialUserIAMact.addWrittenData(writeData);
	  
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(RegularIAMactOne.compromise);
	   attacker.addAttackPoint(bucket.connect);
	   attacker.attack();
      
	   System.out.println("~~~~~ CASE #01: READ ONLY GROUP MEMBER IAM ACCT ('RegularIAMactOne') COMPROMISE ~~~~~");
      
	   ReadOnly.authenticate.assertCompromisedInstantaneously();
	   bucket.connect.assertCompromisedInstantaneously();
	   bucket.authenticate.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   readData.requestAccess.assertCompromisedInstantaneously();
	   readData.read.assertCompromisedInstantaneously();
	   writeData.write.assertUncompromised();

      }
   
   @Test
   public void testgroups_specialcompromise() {
	   
	   System.out.println("########## USE CASE TESTS FOR GROUPS ##########");
	   
	   User AdminUser = new User("AdminUser");	
	   IAMaccount AdminIAMact = new IAMaccount("AdminIAMact");
	   Credentials AdminCred = new Credentials("AdminCred");
	   User RegularUserOne = new User("RegularUserOne");
	   IAMaccount RegularIAMactOne = new IAMaccount("RegularIAMactOne");
	   Credentials RegularCredOne = new Credentials("RegularCredOne");
	   User RegularUserTwo = new User("RegularUserTwo");
	   IAMaccount RegularIAMactTwo = new IAMaccount("RegularIAMactTwo");
	   Credentials RegularCredTwo = new Credentials("RegularCredTwo");
	   User SpecialUser = new User("SpecialUser");
	   IAMaccount SpecialUserIAMact = new IAMaccount("SpecialUserIAMact");
	   Credentials SpecialUserCred = new Credentials("SpecialUserCred");
	   AuthenticationService authServ = new AuthenticationService("authServ");
	   Group ReadOnly = new Group("ReadOnly");
	   Group WriteOnly = new Group("WriteOnly");
	   Bucket bucket = new Bucket("bucket", true, true);
	   Data data = new Data("data");
	   Data readData = new Data("readData");
	   Data writeData = new Data("writeData");
	   
	   AdminUser.addAccounts(AdminIAMact);
	   AdminIAMact.addCredentials(AdminCred);
	   
	   RegularUserOne.addAccounts(RegularIAMactOne);
	   RegularIAMactOne.addCredentials(RegularCredOne);
	   
	   RegularUserTwo.addAccounts(RegularIAMactTwo);
	   RegularIAMactTwo.addCredentials(RegularCredTwo);
	   
	   SpecialUser.addAccounts(SpecialUserIAMact);
	   SpecialUserIAMact.addCredentials(SpecialUserCred);
	   
	   authServ.addAuthenticatedAccounts(AdminIAMact);
	   authServ.addAuthenticatedAccounts(RegularIAMactOne);
	   authServ.addAuthenticatedAccounts(RegularIAMactTwo);
	   authServ.addAuthenticatedAccounts(SpecialUserIAMact);
	   
	   AdminIAMact.addCreatedIAMgroups(ReadOnly);
	   AdminIAMact.addCreatedIAMgroups(WriteOnly);
	   
	   data.addContainedData(readData);
	   data.addContainedData(writeData);
	   bucket.addData(data);
	   bucket.addData(readData);
	   bucket.addData(writeData);
	   bucket.addAccount(ReadOnly);
	   bucket.addAccount(WriteOnly);
	   
	   bucket.addAccount(SpecialUserIAMact);

	   ReadOnly.addMemberIAMaccounts(AdminIAMact);
	   ReadOnly.addMemberIAMaccounts(RegularIAMactOne);
	   ReadOnly.addMemberIAMaccounts(SpecialUserIAMact);
	   ReadOnly.addReadData(readData);
	   
	   WriteOnly.addMemberIAMaccounts(AdminIAMact);
	   WriteOnly.addMemberIAMaccounts(RegularIAMactTwo);
	   ReadOnly.addWrittenData(writeData);
	   
	   SpecialUserIAMact.addWrittenData(writeData);
	  
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(SpecialUserIAMact.compromise);
	   attacker.addAttackPoint(bucket.connect);
	   attacker.attack();
      
	   System.out.println("~~~~~ CASE #02: READ ONLY GROUP MEMBER IAM ACCT WITH SPECIAL PRIVILEGES ('SpecialUserIAMact') COMPROMISE ~~~~~");
      
	   ReadOnly.authenticate.assertCompromisedInstantaneously();
	   bucket.connect.assertCompromisedInstantaneously();
	   bucket.authenticate.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   readData.requestAccess.assertCompromisedInstantaneously();
	   readData.read.assertCompromisedInstantaneously();
	   
	   bucket.connect.assertCompromisedInstantaneously();
	   bucket.authenticate.assertCompromisedInstantaneously();
	   bucket.access.assertCompromisedInstantaneously();
	   bucket._machineAccess.assertCompromisedInstantaneously();
	   writeData.requestAccess.assertCompromisedInstantaneously();
	   writeData.anyAccountWrite.assertCompromisedInstantaneously();
	   writeData.write.assertCompromisedInstantaneously();

      }
   
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
