package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class TestUseCaseInstances {
	
	/*
	 * 		  							  
	 * 		User -> (via AccessKey) -> Instance ---------------
	 * 		  |							  |					   |
	 * 		  |			         Operating System ---		   | 
	 *  	  |							  			|	       |
	 * 		  |										|          |
	 * 		  ---- (via ApplicationAccount) -> Application -> Data
	 * 					      |	
	 * 					 Credentials
	 * 						  |									 
	 * 			    Authentication Service	
	 * 
	 * 
	 * 		User has the key to log onto an instance. That instance runs an application using 
	 * 		an operating system. The user has account on the application that can be used to 
	 * 		access some data.
	 * 
	 * 		Case #01: The attacker is able to steal/compromise to the user's access key for the instance.
	 * 				  They should have complete control over the instance.
	 * 
	 * 		Case #02: The attacker is not able to get the user's access key for the instance, but does
	 * 				  modifies the keys file to try and get access. Ideally, this would work, but would 
	 * 				  require significant effort.		
	 * 
	 * 		Case #03: Attacker is able to get the compromise the user's application account somehow.
	 * 				  Ideally, he should not be able to access the data on the instance via the application
	 * 				  without getting into the instance on the first place.		
	 * 
	 */
	
   @Test
   public void testinstanceskeycompromise() {
	   
	  System.out.println("########## USE CASE TESTS FOR INSTANCES ##########");
	   
	  User user = new User("user");										
	  AccessKey key = new AccessKey("access key");
	  Instance instance = new Instance("instance");
	  OperatingSystem OS_AMI = new OperatingSystem("OS_AMI");
	  Account OSact = new Account("OSact");
	  Data data = new Data("data");
	  Application app = new Application("app");
	  Account appact = new Account("appact");
	  Credentials cred = new Credentials("cred");
	  Data appdata = new Data("appdata");  
	  
	  key.addAssignedInstances(instance);		
	  key.addAssignedOSaccount(OSact);
	  user.addKey(key);
	  instance.addAccount(OSact);
	  instance.addData(data);
	  instance.addExecutees(OS_AMI);
	  OS_AMI.addAssignedAccounts(OSact);
	  OSact.addReadData(data);
	  OSact.addWrittenData(data);
	  OSact.addDeletedData(data);
	  OS_AMI.addExecutees(app);
	  app.addAssignedAccounts(appact);
	  appact.addReadData(appdata);  
	  
	  data.addContainedData(appdata);
	  
	  Attacker attacker = new Attacker();
	  attacker.addAttackPoint(instance.connect);
      attacker.addAttackPoint(key.compromise);
      attacker.attack();
      
      System.out.println("~~~~~ CASE #01: COMPROMISE INSTANCE ACCESS KEY ~~~~~ ");
      
      instance.connect.assertCompromisedInstantaneously();
      instance.access.assertCompromisedInstantaneously();
      OS_AMI.connect.assertCompromisedInstantaneously();
      OS_AMI.authenticate.assertCompromisedInstantaneously();
      OSact.authenticate.assertCompromisedInstantaneously();
      data.requestAccess.assertCompromisedInstantaneously();
      data.read.assertCompromisedInstantaneously();
      data.write.assertCompromisedInstantaneously();
      data.delete.assertCompromisedInstantaneously();
      app.connect.assertCompromisedInstantaneously();
      app.access.assertUncompromised();
      appdata.read.assertCompromisedInstantaneously();								
   
   }
   
   @Test
   public void testinstancesmodifykeysfile() {
	  
	  User user = new User("user");										
	  AccessKey key = new AccessKey("access key");
	  Instance instance = new Instance("instance");
	  OperatingSystem OS_AMI = new OperatingSystem("OS_AMI");
	  Account OSact = new Account("OSact");
	  Data data = new Data("data");
	  Application app = new Application("app");
	  Account appact = new Account("appact");
	  Credentials cred = new Credentials("cred");
	  Data appdata = new Data("appdata");  
	  
	  key.addAssignedInstances(instance);		
	  key.addAssignedOSaccount(OSact);
	  user.addKey(key);
	  instance.addAccount(OSact);
	  instance.addData(data);
	  instance.addExecutees(OS_AMI);
	  OS_AMI.addAssignedAccounts(OSact);
	  OSact.addReadData(data);
	  OSact.addWrittenData(data);
	  OSact.addDeletedData(data);
	  OS_AMI.addExecutees(app);
	  app.addAssignedAccounts(appact);
	  appact.addReadData(appdata);  
	  
	  data.addContainedData(appdata);
	  
	  Attacker attacker = new Attacker();
	  attacker.addAttackPoint(instance.connect);
      attacker.addAttackPoint(key.modifyKeyFile);
      attacker.attack();
      
      System.out.println("~~~~~ CASE #02: MODIFY authorized_keys FILE ~~~~~");
      
      key.modifyKeyFile.assertCompromisedInstantaneously();
      key.compromise.assertCompromisedWithEffort();
      instance.connect.assertCompromisedInstantaneously();
      instance.access.assertCompromisedWithEffort();
      OS_AMI.connect.assertCompromisedWithEffort();
      OS_AMI.authenticate.assertCompromisedWithEffort();
      OSact.authenticate.assertCompromisedWithEffort();
      data.requestAccess.assertCompromisedWithEffort();
      data.read.assertCompromisedWithEffort();
      data.write.assertCompromisedWithEffort();
      data.delete.assertCompromisedWithEffort();
      app.connect.assertCompromisedWithEffort();
      app.access.assertUncompromised();
      appdata.read.assertCompromisedWithEffort();								
   
   }
   
   @Test
   public void testinstancesappactcompromise() {
	  
	  User user = new User("user");										
	  AccessKey key = new AccessKey("access key");
	  Instance instance = new Instance("instance");
	  OperatingSystem OS_AMI = new OperatingSystem("OS_AMI");
	  Account OSact = new Account("OSact");
	  Data data = new Data("data");
	  Application app = new Application("app");
	  Account appact = new Account("appact");
	  Credentials cred = new Credentials("cred");
	  Data appdata = new Data("appdata");  
	  
	  key.addAssignedInstances(instance);		
	  key.addAssignedOSaccount(OSact);
	  user.addKey(key);
	  instance.addAccount(OSact);
	  instance.addData(data);
	  instance.addExecutees(OS_AMI);
	  OS_AMI.addAssignedAccounts(OSact);
	  OSact.addReadData(data);
	  OSact.addWrittenData(data);
	  OSact.addDeletedData(data);
	  OS_AMI.addExecutees(app);
	  app.addAssignedAccounts(appact);
	  appact.addReadData(appdata);  
	  
	  data.addContainedData(appdata);
	  
	  Attacker attacker = new Attacker();
	  attacker.addAttackPoint(instance.connect);
      attacker.addAttackPoint(appact.compromise);
      attacker.attack();
      
      System.out.println("~~~~~ CASE #03: APPLICATION ACCOUNT COMPROMISE ONLY ~~~~~");
      
      instance.connect.assertCompromisedInstantaneously();
      key.compromise.assertUncompromised();
      instance.access.assertUncompromised();
      OS_AMI.connect.assertUncompromised();
      OS_AMI.authenticate.assertUncompromised();
      OSact.authenticate.assertUncompromised();
      data.requestAccess.assertUncompromised();
      data.read.assertUncompromised();
      data.write.assertUncompromised();
      data.delete.assertUncompromised();
      app.connect.assertUncompromised();
      app.access.assertUncompromised();
      appdata.read.assertUncompromised();								
   
   }
   @After
   public void deleteModel() {
           Asset.allAssets.clear();
           AttackStep.allAttackSteps.clear();
           Defense.allDefenses.clear();
   }
}
