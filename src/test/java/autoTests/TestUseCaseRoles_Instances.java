package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseRoles_Instances {
	
	/*
	 * 
	 * 		
	 * 					          Operating System---
	 *  				      			  |			|
	 * 									  |			|
	 * 		User -> (via AccessKey) -> Instance		| 
	 * 		  |							  			|							   
	 * 		  |			                  			|				 Bucket    
	 *  	  |					    	            |				   |
	 * 		  |										|                  |
	 * 		  ---- (via ApplicationAccount) -> Application -> Role -> Data
	 * 					      |						
	 * 			    	 Credentials
	 * 						  |
	 * 				Authentication Service
	 * 
	 * 
	 * 		User has the key to log onto an instance. That instance runs an application using 
	 * 		an operating system. The user also has a separate account on the application that can
	 * 		be used to assume a role which in turn can get access to data stored on a bucket.
	 * 
	 *  	The attacker will have to compromise both the instance access key and the user credentials
	 *  	for	the application. Obviously, compromising either would not work.			
	 * 
	 */

   @Test
   public void testroles_instances() {
	   
	   System.out.println("########## USE CASE TESTS FOR ROLES (INSTANCES) ##########");
	  
	   User user = new User("user");										
	   AccessKey key = new AccessKey("access key");
	   Instance instance = new Instance("instance");						
	   OperatingSystem OS_AMI = new OperatingSystem("OS_AMI");
	   Account OSact = new Account("OSact");
	   Application app = new Application("application"); 	
	   Account appact = new Account("appact");
	   Credentials cred = new Credentials("cred");
	   AuthenticationService authServ = new AuthenticationService("authServ");
	   Bucket bucket = new Bucket("bucket", true, true);
	   Role role = new Role("read role"); 
	   Data data = new Data("readable data");
	   
	   key.addAssignedInstances(instance);		
	   key.addAssignedOSaccount(OSact);
	   user.addKey(key);
	   instance.addAccount(OSact);
	   instance.addExecutees(OS_AMI);
	   OS_AMI.addAssignedAccounts(OSact);
	   OS_AMI.addExecutees(app);
	   app.addAssignedAccounts(appact);
	   appact.addCredentials(cred);
	   appact.addAuthenticatees(role);
	   authServ.addAuthenticatedAccounts(appact);
	   bucket.addAccount(role);
	   bucket.addData(data);
	   role.addReadData(data);
	   
	  
	  Attacker attacker = new Attacker();
      attacker.addAttackPoint(instance.connect);				
      attacker.addAttackPoint(key.compromise);
      attacker.addAttackPoint(cred.read);
      attacker.addAttackPoint(bucket.connect);
      attacker.attack();
      
      instance.authenticate.assertCompromisedInstantaneously();
      OSact.authenticate.assertCompromisedInstantaneously();
      OS_AMI.access.assertCompromisedInstantaneously();
      app.connect.assertCompromisedInstantaneously();
      app.authenticate.assertCompromisedInstantaneously();
      appact.authenticate.assertCompromisedInstantaneously();
      role.authenticate.assertCompromisedInstantaneously();
//    bucket.connect.assertCompromisedInstantaneously();
//    bucket.authenticate.assertCompromisedInstantaneously();
      bucket.access.assertCompromisedInstantaneously();
      data.read.assertCompromisedInstantaneously();
      data.write.assertUncompromised();
      data.delete.assertUncompromised();
	  
      }
   
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
